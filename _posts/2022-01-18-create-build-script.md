---

title: Writing Build script to setup our VM

date: 2022-01-18 15:23:05 +0200

categories: [Build vulnerable VMs,Build script]

tags: vulnerable_VM

---

## Status
- You can run `vagrant status` to check the status of your boxes

![image](https://i.imgur.com/6OqzVDd.png)

- Let's start this with `vagrant up`

## Build script
- Ok what is a build script?
- **Build script** is used to setup the vulnerable VM
- Like we can write set of commands in that file that need to setup the VM

Ex: update, upgrade, installing required tools, setting up the firewall, chaning hostname, changing permissions of files, creating/deleting users, changing passwords for the users
- Ok let's start

```bash
#!/bin/bash
echo "[+] Building our first vulnerable VM"
echo "[+] Getting update"
sudo apt-get update
```
- First let's do an update


```bash
echo "[+] Installing utilities"
apt install -y net-tools open-vm-tools
```
- Now let's install net tools and open vm tools (it's mandatory)


```bash
echo "[+] Configuring hostname"
hostnamectl set-hostname pwn
cat <<EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 pwn
EOF
```
- Changing the hostname of the machine


```bash
echo "[+] Checking users || Creating users"
id -u pwn &>/dev/null || useradd -m pwn
```
- Checking if there's a user named pwn.
#### breakdown that command
```bash
vagrant@ubuntu-focal:~$ id -u pwn &>/dev/null
vagrant@ubuntu-focal:~$ echo $?
1
```
- We can see the return value of a previous command by running `echo $?`
- If the user exists then it'll return 0, Now there's no user  named **pwn**
- So the command next to `||` (or operator) will run `useradd -m pwn`


```bash
echo "[+] Symlinking history files to /dev/null"
ln -sf /dev/null /root/.bash_history
ln -sf /dev/null /home/pwn/.bash_history
```
- After adding the user, Now we are symlinking bash history files to `/dev/null`


```bash
echo "[+] Setting passwords"
echo "root:1hop3Y0uN3veRf1nD7h1sPaSsW0rDDDD" | chpasswd
echo "pwn:w3lc0m379pWn&p41n" | chpasswd
```
- Setting a strong password for user and root


```bash
echo "[+] Clean up"
rm -rf /root/.cache
rm -rf /home/pwn/.cache
```
- Deleting the cache files
- Don't forget to delete your **setup.sh** (build script)
- Coz it contains all information and passwords too
- And delete other files your dropped in

### Full script
```bash
#!/bin/bash
echo "[+] Building our first vulnerable VM"
echo "[+] Getting update"
sudo apt-get update

echo "[+] Installing utilities"
apt install -y net-tools open-vm-tools

echo "[+] Configuring hostname"
hostnamectl set-hostname pwn
cat <<EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 pwn
EOF

echo "[+] Checking users || Creating users"
id -u pwn &>/dev/null || useradd -m pwn

echo "[+] Symlinking history files to /dev/null"
ln -sf /dev/null /root/.bash_history
ln -sf /dev/null /home/pwn/.bash_history

echo "[+] Setting passwords"
echo "root:1hop3Y0uN3veRf1nD7h1sPaSsW0rDDDD" | chpasswd
echo "pwn:w3lc0m379pWn&p41n" | chpasswd

echo "[+] Clean up"
rm -rf /root/.cache
rm -rf /home/pwn/.cache
```
- Now we can run this script in our VM to setup it :D
- So this is called a build script.
- Let's create our first vulnerable VM in next article :)
