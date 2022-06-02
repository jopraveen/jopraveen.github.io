---

title: How to install Vagrant in your operating system

date: 2022-01-18 12:23:05 +0200

categories: [Build vulnerable VMs,Vagrant Setup]

tags: vulnerable_VM

image: "https://i.imgur.com/VDdalHk.png"

---

# Vagrant
- Vagrant is a tool for building and managing virtual machine environments in a single workflow.
- more info [click here](https://www.vagrantup.com/intro)

## Download
- Head up to [this link](https://www.vagrantup.com/downloads) and download vagrant for your operating system
- After installing you can access it via terminal
- check if it's downloaded properly `vagrant -v`


 ## Setup
 
 - You can install whatever you want
 - Go to [this link](https://app.vagrantup.com/boxes/search) and choose your box

![](https://i.imgur.com/NY7aAtz.png)

- Also you can select the provider, so vagrant will run it in that provider
- Here I'm going to select Virtual box, because I have installed that in my system

![image](https://i.imgur.com/3zb3XfC.png)

- Let's download this Box
```console
vagrant box add ubuntu/focal64
```
- Run this command on your terminal to install this box.
- Wait few minutes for the download.
- I'm using Windows as my base machine, Commands are pretty simlar, so don't worry :)

![image](https://i.imgur.com/w7jEl1V.png)

- Now run these two commands to setup that box
-  Before running this commands create two directories
```console
mkidr box data
```
- Now go to  box directory

```console
vagrant init ubuntu/focal64
```
- And run this command

![image](https://i.imgur.com/jTFFSH9.png)

- This command generates a Vagrantfile
- Which you can use to configure the vm size,networks,synced folders and more...
- `data` folder has shared files between your Vm and your base machine
- You can put your custom binaries, setup.sh, required files to setup the vulnerable site and more in `data` folder
```console
config.vm.synced_folder "../data", "/vagrant_data"
```
- Uncomment the above line in **Vagrantfile** to share those files to your VM
- Also I'm setting a public network to access my VM in local
```console
 config.vm.network "public_network"
```
- Uncomment this line to do that :)
- Now time to start this VM

![image](https://i.imgur.com/6IPrhIh.png)

- You can run `vagrant up` to start your VM
- Now you can simply ssh into this machine using `vagrant ssh` command

![image](https://i.imgur.com/qYiFVoJ.png)

- Great that's all, Now you can use this :D

![image](https://i.imgur.com/1riUASS.png)

- Here you can see, vargrant uses Virtualbox to host this.

![image](https://i.imgur.com/aWb7d0T.png)

- You can also login into this VM with default credentials
- user: `vagrant:vagrant`
- root: `root:vagrant`

![image](https://i.imgur.com/XMjjNYT.png)

- You can shutdown your VM using `vagrant halt`
- If you want to force shutdown, then use `vagrant destroy` command

![image](https://i.imgur.com/RIkfgEx.png)
- Let's setup our vm with a **build script** in next article :)
