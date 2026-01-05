# eBPF XDP Load Balancer

This project implements a Layer 4 Load Balancer using eBPF/XDP. It consists of a kernel-space program (`xdp_lb.c`) and a user-space loader (`xdp_loader.c`).

## Prerequisites

This project requires a Linux environment with eBPF build tools. Since you are running on Windows, we recommend using a full WSL2 distribution like **Ubuntu**.

**Note**: The default `docker-desktop` WSL distribution is too minimal to build this project.

### 1. Install Ubuntu on WSL (If not already installed)
Open Powershell as Administrator and run:
```powershell
wsl --install -d Ubuntu
```
After installation, restart your terminal and open the Ubuntu shell.

### 2. Install Build Dependencies
Inside your Ubuntu WSL shell, run:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev make gcc-multilib build-essential
```

## Compilation

Navigate to the project directory (accessible in WSL via `/mnt/c/...`):
```bash
cd /mnt/c/Users/User/Desktop/nothing/loadbalancer
make
```
This will generate `xdp_loader` (binary) and `xdp_lb.o` (BPF object).

## Running the Load Balancer

### Option A: Test with Virtual Interfaces (Safe)
To separate test traffic from your main network, create a virtual ethernet pair:
```bash
# Create veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

# Assign IP to veth1 (the "client")
sudo ip addr add 192.168.1.5/24 dev veth1

# Run the loader on veth0 (the "load balancer")
sudo ./xdp_loader veth0
```
In another terminal, send traffic:
```bash
ping 192.168.1.100 -I veth1
```
(Note: You won't get a reply unless you set up the backend server application and routing, but you will see the packet counters increase in the `xdp_loader` output).

### Option B: Real Interface (Advanced)
**Warning**: Attaching XDP to your primary network interface (e.g., `eth0`) may disrupt your network connection if not configured correctly.
```bash
sudo ./xdp_loader eth0
```

## Project Structure
- `xdp_lb.c`: Kernel-side XDP program. Parses packets and redirects.
- `xdp_loader.c`: User-side program. Loads BPF object, manages maps, reads stats.
- `common.h`: Shared data structures.
- `Makefile`: Build rules.
