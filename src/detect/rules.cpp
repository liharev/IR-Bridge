#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/reflection.h>

#include <cstdlib>

#include "commands.pb.h"
#include "complex/poll_for_event.pb.h"
#include "gui/picture_id.pb.h"
#include "gui/screen.pb.h"
#include "gui/widget.pb.h"
#include "irbridge/detect.hpp"
#include "misc/leds.pb.h"
#include "misc/rgb_leds.pb.h"

namespace irbridge::detect {

namespace gp = google::protobuf;

std::string Rule::label() const {
  switch (type) {
    case Type::GuiPicture: {
      std::string s = "gui_picture";
      for (std::size_t i = 0; i < picture_ids.size(); ++i) {
        s += i == 0 ? ":" : ",";
        s += gui::picture_id::PictureId_Name(static_cast<gui::picture_id::PictureId>(picture_ids[i]));
      }
      return s;
    }
    case Type::GuiText: return "gui_text:" + regex_source;
    case Type::GuiCustomerPicture: {
      std::string s = "gui_customer_picture";
      for (std::size_t i = 0; i < names.size(); ++i) s += (i == 0 ? ":" : ",") + names[i];
      return s;
    }
    case Type::Leds: {
      std::string s = "leds";
      if (green) s += *green ? ":green" : ":green_off";
      if (red) s += *red ? ":red" : ":red_off";
      return s;
    }
    case Type::RgbColor: {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "rgb_color:%06X", color & 0xFFFFFFu);
      return buf;
    }
    case Type::TurnstilePass: return "turnstile_pass";
  }
  return "unknown";
}

void Rule::compile() {
  if (type != Type::GuiText) return;
  auto flags = std::regex::ECMAScript;
  // Cyrillic case folding is done on the text and pattern before matching (std::regex icase
  // works only on single bytes).
  const std::string src = icase ? util::utf8_to_lower(regex_source) : regex_source;
  regex.emplace(src, flags);
}

RuleSet RuleSet::defaults() {
  RuleSet rs;
  Rule a;
  a.type = Rule::Type::GuiPicture;
  a.picture_ids = {gui::picture_id::APPROVED, gui::picture_id::APPROVED_DISCOUNT};
  rs.approve.push_back(a);
  Rule g;
  g.type = Rule::Type::Leds;
  g.green = true;
  rs.approve.push_back(g);
  Rule t;
  t.type = Rule::Type::TurnstilePass;
  rs.approve.push_back(t);

  Rule r;
  r.type = Rule::Type::GuiPicture;
  r.picture_ids = {gui::picture_id::REJECTED};
  rs.reject.push_back(r);
  Rule rl;
  rl.type = Rule::Type::Leds;
  rl.red = true;
  rs.reject.push_back(rl);
  return rs;
}

namespace {

// What a single command shows to the passenger.
struct UiFacts {
  std::vector<int> pictures;
  std::vector<std::string> texts;
  std::vector<std::string> customer_pictures;
  std::optional<misc::leds::Leds> leds;
  std::vector<std::uint32_t> rgb_colors;
  bool turnstile_pass = false;
};

void collect_widget(const gui::widget::Widget& w, UiFacts& f, int depth = 0) {
  if (depth > 32) return;  // defensive: malformed or hostile nesting
  switch (w.widget_case()) {
    case gui::widget::Widget::kVerticalLayout:
      for (const auto& c : w.vertical_layout().widgets()) collect_widget(c, f, depth + 1);
      break;
    case gui::widget::Widget::kHorizontalLayout:
      for (const auto& c : w.horizontal_layout().widgets()) collect_widget(c, f, depth + 1);
      break;
    case gui::widget::Widget::kText:
      f.texts.push_back(w.text().text());
      break;
    case gui::widget::Widget::kPicture:
      f.pictures.push_back(w.picture().picture_id());
      break;
    case gui::widget::Widget::kCustomerPicture:
      f.customer_pictures.push_back(w.customer_picture().name());
      break;
    case gui::widget::Widget::kGeneratedText:
      f.texts.push_back(w.generated_text().prefix());
      break;
    default:
      break;
  }
}

void collect_screen(const gui::screen::ShowScreen& s, UiFacts& f) {
  if (s.has_root()) collect_widget(s.root(), f);
}

void collect_ui(const complex::poll::UserInterface& ui, UiFacts& f) {
  if (ui.has_set_leds_state()) f.leds = ui.set_leds_state();
  if (ui.has_show_screen()) collect_screen(ui.show_screen(), f);
}

UiFacts facts_of(const proto::DecodedCommand& cmd) {
  UiFacts f;
  if (!cmd.wrapper) return f;
  switch (static_cast<proto::ModuleId>(cmd.key.module)) {
    case proto::ModuleId::Gui: {
      const auto& g = static_cast<const ::Gui&>(*cmd.wrapper);
      if (g.has_show_screen()) collect_screen(g.show_screen(), f);
      break;
    }
    case proto::ModuleId::Misc: {
      const auto& m = static_cast<const ::Miscellaneous&>(*cmd.wrapper);
      if (m.has_set_leds_state()) f.leds = m.set_leds_state();
      if (m.has_set_all_rgb_leds()) f.rgb_colors.push_back(m.set_all_rgb_leds().color());
      if (m.has_set_rgb_leds()) {
        for (const auto& l : m.set_rgb_leds().leds()) f.rgb_colors.push_back(l.color());
      }
      if (m.has_set_rgb_leds_by_mask()) {
        for (auto c : m.set_rgb_leds_by_mask().colors()) f.rgb_colors.push_back(c);
      }
      break;
    }
    case proto::ModuleId::Turnstile: {
      const auto& t = static_cast<const ::Turnstile&>(*cmd.wrapper);
      f.turnstile_pass = t.has_allow_one_pass();
      break;
    }
    default:
      break;
  }
  return f;
}

bool color_close(std::uint32_t a, std::uint32_t b, std::uint32_t tol) {
  for (int shift : {16, 8, 0}) {
    const int ca = static_cast<int>((a >> shift) & 0xFF);
    const int cb = static_cast<int>((b >> shift) & 0xFF);
    if (static_cast<std::uint32_t>(std::abs(ca - cb)) > tol) return false;
  }
  return true;
}

// Returns true and fills passengers when the rule matches the facts.
bool match(const Rule& r, const UiFacts& f, int& passengers) {
  passengers = 1;
  switch (r.type) {
    case Rule::Type::GuiPicture:
      for (int p : f.pictures) {
        for (int id : r.picture_ids) {
          if (p == id) return true;
        }
      }
      return false;
    case Rule::Type::GuiText:
      if (!r.regex) return false;
      for (const auto& t : f.texts) {
        const std::string subject = r.icase ? util::utf8_to_lower(t) : t;
        std::smatch m;
        if (std::regex_search(subject, m, *r.regex)) {
          if (m.size() > 1 && m[1].matched) {
            const long n = std::strtol(m[1].str().c_str(), nullptr, 10);
            if (n >= 1 && n <= 10) passengers = static_cast<int>(n);
          }
          return true;
        }
      }
      return false;
    case Rule::Type::GuiCustomerPicture:
      for (const auto& p : f.customer_pictures) {
        for (const auto& n : r.names) {
          if (p == n) return true;
        }
      }
      return false;
    case Rule::Type::Leds: {
      if (!f.leds) return false;
      const auto& l = *f.leds;
      if (r.green) {
        // A rule on green=true requires green on and red not on.
        if (!l.has_green() || l.green() != *r.green) return false;
        if (*r.green && l.has_red() && l.red()) return false;
      }
      if (r.red) {
        if (!l.has_red() || l.red() != *r.red) return false;
      }
      return r.green.has_value() || r.red.has_value();
    }
    case Rule::Type::RgbColor:
      for (auto c : f.rgb_colors) {
        if (color_close(c, r.color, r.tolerance)) return true;
      }
      return false;
    case Rule::Type::TurnstilePass:
      return f.turnstile_pass;
  }
  return false;
}

RuleMatch evaluate_facts(const RuleSet& rs, const UiFacts& f) {
  RuleMatch m;
  int pax = 1;
  for (const auto& r : rs.reject) {
    if (match(r, f, pax)) {
      m.indication = Indication::Reject;
      m.rule = r.label();
      return m;
    }
  }
  for (const auto& r : rs.approve) {
    if (match(r, f, pax)) {
      m.indication = Indication::Approve;
      m.rule = r.label();
      m.passengers = pax;
      return m;
    }
  }
  return m;
}

bool is_write_name(const std::string& n) {
  static const char* kWords[] = {"write", "set_counter", "modify", "copy_counter", "commit", "increment",
                                 "update",  "append"};
  for (const char* w : kWords) {
    if (n.find(w) != std::string::npos) return true;
  }
  return false;
}

}  // namespace

RuleMatch RuleSet::evaluate(const proto::DecodedCommand& cmd) const { return evaluate_facts(*this, facts_of(cmd)); }

RuleMatch RuleSet::evaluate_complex_event_ui(const proto::DecodedCommand& cmd) const {
  if (!cmd.wrapper || static_cast<proto::ModuleId>(cmd.key.module) != proto::ModuleId::Complex) return {};
  const auto& c = static_cast<const ::Complex&>(*cmd.wrapper);
  if (!c.has_poll_for_event() || !c.poll_for_event().has_on_event_ui_action()) return {};
  UiFacts f;
  collect_ui(c.poll_for_event().on_event_ui_action(), f);
  return evaluate_facts(*this, f);
}

bool is_card_write(const proto::DecodedCommand& cmd) {
  const auto m = static_cast<proto::ModuleId>(cmd.key.module);
  if (m != proto::ModuleId::Mifare && m != proto::ModuleId::MifareExt && m != proto::ModuleId::Cipurse &&
      m != proto::ModuleId::Troika) {
    return false;
  }
  if (is_write_name(cmd.key.name)) return true;
  if (cmd.key.name.find("bulk") == std::string::npos || !cmd.wrapper) return false;
  // Bulk operation: a write if any inner operation writes.
  const gp::Reflection* r = cmd.wrapper->GetReflection();
  const gp::FieldDescriptor* fd = cmd.wrapper->GetDescriptor()->FindFieldByName(cmd.key.name);
  if (fd == nullptr || fd->cpp_type() != gp::FieldDescriptor::CPPTYPE_MESSAGE) return false;
  const gp::Message& bulk = r->GetMessage(*cmd.wrapper, fd);
  const gp::FieldDescriptor* ops = bulk.GetDescriptor()->FindFieldByName("operations");
  if (ops == nullptr || !ops->is_repeated()) return false;
  const gp::Reflection* br = bulk.GetReflection();
  for (int i = 0; i < br->FieldSize(bulk, ops); ++i) {
    const gp::Message& op = br->GetRepeatedMessage(bulk, ops, i);
    const gp::Descriptor* od = op.GetDescriptor();
    for (int k = 0; k < od->oneof_decl_count(); ++k) {
      const gp::FieldDescriptor* set = op.GetReflection()->GetOneofFieldDescriptor(op, od->oneof_decl(k));
      if (set != nullptr && is_write_name(set->name())) return true;
    }
  }
  return false;
}

}  // namespace irbridge::detect
