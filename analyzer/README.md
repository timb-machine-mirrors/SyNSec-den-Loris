# Loris Analyzer

## Installation
```Bash
docker image build -t loris-analyzer:python -f Dockerfile.python .
docker container create -it -v $(pwd):/loris_analyzer -v $(pwd)/../emulator:/loris_analyzer_deps/emulator --name loris-analyzer-python loris-analyzer:python

docker image build -t loris-analyzer:dev -f Dockerfile.dev .
docker container create -it -v $(pwd):/loris_analyzer -v $(pwd)/../emulator:/loris_analyzer_deps/emulator -v $(pwd)/../../mustbastani/angr:/angr-dev/angr --name loris-analyzer-dev loris-analyzer:dev
```
Pypy cannot fully run emulator. So, we need to use Python to save a loader snapshot. Run the following command in the 
`loris-analyzer-python` container.
```Bash
python3 loris_analyzer.py -n 1 --debug --firmwire-log debug --angr-log info -b modem_files/CP_G973FXXSHHWI1_CP25062570_CL25257816_QB71477174_REV01_user_low_ship.tar.md5
```

```Bash
docker image build -t loris-analyzer -f Dockerfile .
docker container create -it -v $(pwd):/loris_analyzer -v $(pwd)/../emulator:/loris_analyzer_deps/emulator --name loris-analyzer loris-analyzer
```

```Bash
source /root/.virtualenvs/angr/bin/activate
python3 loris_analyzer.py --debug --angr-log debug --firmwire-log debug -b md1img.img
```