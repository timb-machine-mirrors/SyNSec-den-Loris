# Loris

## Installation
```Bash
docker image build -t loris .
docker container run -it -v $(pwd):/loris --name loris loris
```

```Bash
cargo build --release

cd emulator
pip3 install -r requirements.txt
# /loris/emulator :: run the following command to check the address of LORIS_SAEL3 address, like: 0x4b000001
cd modkit/ && make && cd ..
./firmwire.py -t loris_sael3 modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
# /loris/emulator :: run the following commands to remove fuzz base snapshot and compile baseband tasks
cd modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4_workspace/ && rm snapshots.qcow2 fuzz_base.snapinfo && cd ../..
# /loris/emulator :: run the following command to create fuzz base snapshot
./firmwire.py -t loris_sael3 --snapshot-at 0x4b000000,fuzz_loris_sael3 --exclusive SAEL3,LORIS_SAEL3,Background --before-launch /loris/emulator/firmwire/vendor/shannon/G973FXXU3ASG8.py modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
./firmwire.py -t sael3 --snapshot-at 0x4b000000,fuzz_afl_sael3 --exclusive SAEL3,AFL_SAEL3,Background --before-launch /loris/emulator/firmwire/vendor/shannon/G973FXXU3ASG8.py modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
# /loris :: fuzz
cargo run --release -- fuzz --grammar grammars/sec_mode_cmd.loris --firmwire-ex --debug-child -- /loris/emulator/firmwire.py --debug --restore-snapshot fuzz_base --fuzz loris_sael3 --fuzz-input @@ --exclusive SAEL3,LORIS_SAEL3,Background --before-launch /loris/emulator/firmwire/vendor/shannon/G973FXXU3ASG8.py /loris/emulator/modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
```

Fuzz:
```Bash
cargo run --release -- fuzz --grammar grammars/sec_mode_cmd.loris -i eval/fuzz/1/transitions.0x3c7b.d/ -o eval/fuzz/1/ -- /loris/emulator/firmwire.py --consecutive-ports 13130 --restore-snapshot fuzz_base --fuzz loris_sael3 --fuzz-input @@ --exclusive SAEL3,LORIS_SAEL3,Background --before-launch /loris/emulator/firmwire/vendor/shannon/G973FXXU3ASG8.py /firmwire/modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4 > eval/fuzz/1/fuzzer.log 2>&1 &
```

Triage:
```Bash
cargo run --release -- fuzz-triage -i eval/fuzz/1/corpus -- /loris/emulator/firmwire.py --debug --restore-snapshot fuzz_base --fuzz-triage loris_sael3 --fuzz-input @@ --exclusive SAEL3,LORIS_SAEL3,Background --consecutive-ports 13131 --before-launch /firmwire/firmwire/vendor/shannon/G973FXXU3ASG8.py /firmwire/modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
cat 5/coverage/coverage_idx_* | grep '^0x' | cut -d"," -f3 | sed '/^$/d' | sort -u > 5/coverage.txt
```
