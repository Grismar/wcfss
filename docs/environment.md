# Dev environment setup

Rustup needs to be installed on both Windows and Ubuntu.

Set up WSL2 with a custom name:
`wsl --install -d Ubuntu-22.04`
`wsl --export Ubuntu-22.04 D:\Temp\ubuntu-22.04.tar`
`wsl --import ubuntu-wcfss D:\WSL\ubuntu-wcfss D:\Temp\ubuntu-22.04.tar --version 2`
`wsl --terminate Ubuntu-22.04`

In Ubuntu:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable
sudo apt update
sudo apt install -y build-essential
```