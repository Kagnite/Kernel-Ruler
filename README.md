# 🧑‍💻 Kernel Ruler

A modern terminal-based **process monitoring tool** built with **Go**, **eBPF**, and the [Bubble Tea](https://github.com/charmbracelet/bubbletea) TUI framework.  
Think of it like `htop` + `pstree`, but focused on **real-time process execution tracking**.

---

## 🎥 Demo
![KernelRuler Demo](docs/demo.gif)

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
## Keys
  ↑/↓   Navigate process list
  /     Search & filter
  t     Toggle tree view
  enter Show process details
  k     Kill selected process
  q     Quit

### Prerequisites - Go 1.21+ - Linux with eBPF support - Kernel headers installed (for building BPF program)
