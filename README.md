# Kernel Ruler

A modern terminal-based **process monitoring tool** built with **Go**, **eBPF**, and the [Bubble Tea](https://github.com/charmbracelet/bubbletea) TUI framework.  
It’s like `htop`, but focuses on **real-time process execution tracking** since the moment you launch it.

## 🎥 Demo

Here’s how Kernel-Ruler looks in action:

![Demo](docs/demo.gif)

---

## ✨ Features
- 📡 Uses **eBPF** to hook into `execve` syscalls and capture new processes.  
- 📝 Live list of processes with PID, command, and timestamp.  
- 🌳 **Tree view**: visualize process hierarchy (parent/child).  
- 🔍 **Search and filter** by process name.  
- ⚡ Press **k** to kill a process directly from the UI.  
- 📜 **Details view**: see PID, PPID, user, status, and full command.  
- 📊 Sparkline chart showing process execution rate.  
- 🎨 Clean terminal UI powered by Bubble Tea + Lipgloss.  

---

## 📦 Installation

### Prerequisites
- Go 1.21+  
- Linux with eBPF support  
- Kernel headers installed (for building BPF program)  

### Build
```bash
git clone https://github.com/Kagnite/Kernel-Ruler.git
cd Kernel-Ruler
go build -o kernelruler main.go

sudo ./kernelruler
