# 🧑‍💻 Kernel Ruler

A modern terminal-based **process monitoring tool** built with **Go**, **eBPF**, and the [Bubble Tea](https://github.com/charmbracelet/bubbletea) TUI framework.  
Think of it like `htop` + `pstree`, but focused on **real-time process execution tracking**.

---

## 🎥 Demo
![KernelRuler Demo](docs/demo.webp)

---

## ✨ Features
- 📡 Hooks into `execve` syscalls with **eBPF** to capture new processes instantly.  
- 📝 Live, filterable list of processes with PID, command, timestamp.  
- 🌳 **Tree view**: visualize parent/child process hierarchy.  
- 📜 **Details panel**: PID, PPID, user, status, full command (from `/proc`).  
- ⚡ Press **k** to kill a process directly from the UI.  
- 🔍 Search & filter by process name.  
- 🎨 Clean TUI powered by Bubble Tea + Lipgloss.  

---

## 🚀 Installation (from source)

```bash
git clone https://github.com/Kagnite/Kernel-Ruler.git
cd Kernel-Ruler
go build -o kernelruler main.go
sudo ./kernelruler
```
## 🐳 Installation & Run with Docker

```
git clone https://github.com/Kagnite/Kernel-Ruler.git
cd Kernel-Ruler

# Build Docker image (make sure you spelled kernelruler correctly!)
docker build -t kernelruler:test .

# Mount bpffs if not already mounted
sudo mount -t bpf bpf /sys/fs/bpf || true

# Run the container
docker run --rm -it \
  --privileged \
  --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug \
  kernelruler:test
```
## Run in background

```
docker run -d -it --name kernelruler \
  --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug \
  kernelruler:test
```
## Attach later:
```
docker attach kernelruler
# Detach without killing: Ctrl+P then Ctrl+Q
```
## Restart:
```
docker start -ai kernelruler
```
## ⌨ Usage:
```
  ↑/↓   Navigate process list
  /     Search & filter
  t     Toggle tree view
  enter Show process details
  k     Kill selected process
  q     Quit
```
## ⚙ Prerequisites - Go 1.21+ - Linux with eBPF support - Kernel headers installed (example on Debian/Ubuntu):
bash
  sudo apt install linux-headers-$(uname -r)
