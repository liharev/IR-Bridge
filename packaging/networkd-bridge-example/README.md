# Bridge mode (capture.mode: bridge)

The module does not configure the bridge itself. Example for systemd-networkd:

1. Insert the CAMAI unit between the controller and the validators' switch: `eth0` towards
   the controller, `eth1` towards the validators.
2. Copy `10-br0.netdev`, `20-br0-ports.network`, `30-br0.network` to `/etc/systemd/network/`
   and adjust the port names.
3. `systemctl restart systemd-networkd`; check with `networkctl status br0`.
4. In `/etc/camai/irbridge.yaml`: `capture.mode: bridge`, `capture.interface: br0`.

The bridge has no IP address, so the unit stays invisible on the validators' network. If the
unit loses power, traffic stops: for buses use a switch with a mirror port (mode `mirror`)
or a bypass relay where fail-open behaviour is required.
