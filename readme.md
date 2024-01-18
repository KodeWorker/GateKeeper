# GateKeeper

## Contents
1. [Description](#description)
2. [Project Structure](#project-structure)
3. [Progress](#progress)

## Description

### Instruction
1. Generate RSA private key with corresponding length (3072)
```
mkdir key
openssl genrsa -out key/private-key.pem 3072
```
2. Build and install GateKeeper
```
mkdir build && cd build
cmake .. && cmake --build . --config release && cmake --install .
```
3. Run tests and Demo app
```
cd bin
./GateKeeper_test
./GateKeeper_app
```
## Project Structure

## Progress