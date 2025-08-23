# 🛡️ Code Repository for **Praus: Personalized Reveal After Unscripted Shuffling**

## 📁 Folder Structure

- **`CTAuditor/`**  
  Contains the **auditor** code.

- **`CTClient/`**  
  Contains the **client** code.

- **`CTCollector/`**  
  Responsible for **information and statistics collection** throughout the protocol process.  
  It also spawns the client, auditor, and collects runtime metrics.

- **`CTPinger/`**  
  A lightweight server that periodically **pings the auditor** to check liveness, mostly for debugging.

---

## 🚀 Getting Started

This system is intended to run on **AWS EC2** instances.

### ✅ 1. Set Up AWS

- Ensure you have an active **AWS account**.
- Launch an **EC2 instance** using:  
  **Amazon Linux 2023 AMI 2023.7.20250331.0 (x86_64 HVM kernel-6.1)**  
- Inbound rules:
  - ✅ **Allow HTTPS traffic**
  - ✅ **Allow HTTP traffic**
- Once inside the EC2 instance, configure AWS CLI:
  ```bash
  sudo su
  aws configure
  ```

---

### ⚙️ 2. Install Go

Make sure the **Go programming language** is installed:
```bash
sudo yum install -y go
```

---

### 📥 3. Clone the Repository

> **Note:** The current GitHub link is view-only. Use the command below to clone from the anonymous organization:

```bash
sudo yum install -y git
git clone https://github.com/usenix26anonymous/anonymous_net
```

---

### 📂 4. Navigate to CTCollector

```bash
cd anonymous_net/CTCollector
```

---

### ▶️ 5. Start the Protocol

Run the following as root:
```bash
go run main.go
```

This will:
- Start the **CTCollector**
- Launch the protocol with **20 clients** (with 2 sitting out), this is the setup with 1 shuffler and shuffle under 10 keys 
- Generate a `report.json` file in the current folder

---

### 🔧 Running with More Settings

To run under a wide variety of settings, edit the following line in `main.go` (around line 23):

```go
  	total_clients := []uint32{20}
	number_of_shufflers := []uint32{1}
	number_of_keys_shufflers_use := []uint32{10}
	sitout_percent := float64(0.1)
```

Replace it with for example more clients:
```go
total_clients := []uint32{100, 80, 60, 40, 20}
```
Note that the system will run ***all combinations*** of these settings

---

## 💻 Local Testing

To run the protocol **locally** (without networking/RPC):

📂 Go to the `FTChainingZKNonInteractive/` folder and refer to its `README.md`.  
This version runs with **local logging only** and is useful for lightweight debugging and testing.

## Network condition recovery
Sometimes, certain aws machines may experience some issues as you launch too many. If such an issue has caused the auditor to come to a halt, please shut down all running instances except the collector, and rerun the collector. Any experiments that have been completed will have their record written into report.json, please save a copy
