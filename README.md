# Crystal Broadlink

A simple Crystal API for controlling IR controllers from [Broadlink](http://www.ibroadlink.com/). At present, the following devices are currently supported:

> **bold** devices names has been tested successfully

* [SP1](./src/devices/sp1.cr)
* [SP2](./src/devices/sp2.cr)
  - SP2
  - Honeywell SP2
  - SPMini
  - SP3
  - OEM branded SP3
  - SP3S
  - [**SPMini2**](#spmini2)
  - OEM branded SPMini
  - OEM branded SPMini2
  - SPMiniPlus
* [RM](./src/devices/rm.cr)
  - RM2
  - RM Mini
  - RM Pro Phicomm
  - RM2 Home Plus
  - RM2 Home Plus GDT
  - RM2 Pro Plus
  - RM2 Pro Plus2
  - RM2 Pro Plus3
  - RM2 Pro Plus_300
  - RM2 Pro Plus BL
  - RM2 Pro Plus HYC
  - RM2 Pro Plus R1
  - RM2 Pro PP
  - RM Mini Shate
* [A1](./src/devices/a1.cr)
* [Mp1](./src/devices/mp1.cr)
  - MP1
  - Honyar oem mp1
* [Hysen](./src/devices/hysen.cr)
  - Hysen controller
* [S1C](./src/devices/s1c.cr)
  - S1 (SmartOne Alarm Kit)
* [Dooya](./src/devices/dooya.cr)
  - Dooya DT360E (DOOYA_CURTAIN_V2)

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  broadlink:
    github: faustinoaq/broadlink
```

## Usage

```crystal
require "broadlink"

Broadlink.discover(timeout: 3) # get your local ip by connecting to 8.8.8.8:53
Broadlink.discover(timeout: 3, local_ip_adress: "192.168.0.10")
```

TODO: Write usage instructions here

## Development

TODO: Write development instructions here

## Contributing

1. Fork it (<https://github.com/faustinoaq/broadlink/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [mjg59](https://github.com/mjg59) Matthew Garrett - original author
- [faustinoaq](https://github.com/faustinoaq) Faustino Aguilar - creator, maintainer
