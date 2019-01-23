# **Proof of Concept: Booked on Blockchain, BOBChain**

BOBChain is an implementation of a blockchain. The blockchain technology powering BOBChain is *TrustChain* created by Tribler at the Technical University of Delft.

The aim of this document is to give the reader insights into:

- Why BOBChain
- Architecture of BOBChain.
- How to make use of BOBChain.
- Challenges that still need to be faced on POC: BOBChain.

---

### **Why BOBChain?**

![alt text](https://github.com/simionAndrei/BobChain/blob/master/images/bob_simple.jpg "BoBChain Simple Diagram")

### **The Problem:**

Globalization, budget airlines and the sharing economy have lead to an increase in the tourism market around the world. Highly popular touristic cities such as London, Paris, Amsterdam, etc. are experiencing a high influx of tourists. Due to the rise in tourism it has become profitable and exceedingly easy to out ones home too incoming tourists by services such as AirBnB. The increase in tourism and the rise in sharing economy, has lead to some cities to overflow. Causing grief to permanent residents of these cities.

Some of the effects of over-tourism are:

- Overcrowding of popular tourist attractions/areas
- Housing market prices SkyRocketing
- Permanent residence have issues with noise pollution
- Cities transportation infrastructure being overcrowded

Over-tourism has caused enough problems that municipality are taking notice and implementing laws to contest the ever growing increase of tourists. Some of these laws are looking at Online Travel Agencies (**OTAs**) to limit the amount of nightcaps residents are allowed to rent out their homes.  This should reduce the amount of homes bought to directly rent out to tourists due to it becoming less profitable.

The main issue with this enforcement is that OTAs do not have a platform where they can communicate with one another to see if residents, who are on multiple OTAs, are exceeding the nightcaps. At the moment OTAs can only internally check their service to see if a resident is exceeding nightcaps, allowing residents to use multiple OTA platforms to avoid such restrictions.

### **Why blockchain?**

The rise in popularity of *blockchain technology* has been immense since cryptocurrencies like *bitcoin*, *Ethereum*, *Ripple*, etc. entered the attention of mainstream media outlets. Blockchain technology has also been implemented outside of being a currency, the rise of enterprise solutions like *Ethereum Smart-Contracts*, *HyperLedger*, *TrustChain*, etc.. Many different problems have been thrown at the new technology to see if it offers a viable solution.

Over-tourism in cities has led to municipalities creating legal barriers for home-owners with limiting the amount of nights a house can be rented out for. To ensure these limits are met municipalities are putting increasing pressure and in-some cases legal consequences to OTAs to enforce these nightcaps on their customers/partners.

OTAs have noticed the increase in legal consequences for having customers/partners exceed the legal nightcap limits of certain properties. Foreseeing a future where OTAs must check when a booking is made that the home-owner has not exceeded his/her legal nightcap limit with other OTAs. Blockchain offers a unique solution to this problem, seeing as if API calls were made between platforms a worry exists that this may lead to cartel forming or be viewed as companies creating cartels.

Having a decentralized way of checking if nightcap limits are not exceeded, allows for the OTAs to ensure the laws of the municipality are being followed. Without having to worry that a cartel is being formed. Blockchain at first glance is the perfect solution for this problem. Since it allows for a decentralized ledger to be created, without having a central party control how it is run.

### **BOBChain Features**

**BOBChain** offers a blockchain solution to tackle the problem of legal nightcap limits that will allow current and future OTA to communicate on a decentralized ledger to ensure that no legal limits are exceeded.

**BOBChain** offers a blockchain solution to tackle the dreaded overbooking, currently there is no central platform to check if an accommodation that is put up for rent on multiple OTA sites is double booked. The overbooking issue costs the OTAs money as an overbooking means they must usually refund or find a new accommodation for the booking customer.

**BOBChain** offers a blockchain solution with authorized homeowner licenses from municipalities, these licenses can be shared by the homer-owner to different OTAs. The OTAs with these licenses can ensure no overbookings take place or nightcap limits are exceeded.

**BOBChain** offers a blockchain solution that is decentralized and anonymous between the bookings of different OTA parties. Ensuring the privacy between different OTAs. Meaning no valuable business information is exchanged between OTAs.

---

## **Architecture of BOBChain**

BOBChain is a direct extension of Triblers *TrustChainCommunity*; with some modifications to the validation of transactions and communications with other TrustChainCommunities. BOBChain's artitecture is centered around the idea that every homeowner gets a license and this license is seen as an accommodations private *TrustChain* or in this case a *BOBChain*. A design choice was made to have the municipality and OTAs run the TrustChainCommunities for the home-owners. Allowing *BOBChain* not to depend on homeowners keeping the service running but the municipality and OTAs.

To better describe the architecture of BOBChain the process of how a homeowner is able to get a license, to authorize an OTA to use its license and how an OTA or Municipality can interact with the license.

### **Homeowner Attaining a License**

To ensure each homeowner is a private *BOBChainCommunity*, the homeowner must attain a license from the municipality. The advantage of registering the home with the municipality is that the municipality is able to monitor all the homes on the market.

The creation of the private *BOBChainCommunity* is done by generating a private and public key pair for the home-owner and storing it on local servers. The municipality will create a *genesis* block with the private and public key-pair of the homeowner, which will act as an agreement and a license for the homeowner. Too ensure that chains are kept up-to-date the municipality will have to continuously run all the *BOBChainCommunities* and store their respective BOB Chains in the database.

### **Home-owner Authorizing use of a License**

Once a homeowner has registered his or her home, it can go to an OTA and authorize it to use it. This can either be done by registering the address by the OTA or giving the public-key the homeowner was given during the creation of the license. From here the OTA can request the private and public key pair to start the *BOBChainCommunity*.


Once a key pair has been acquired the OTA can start the *BOBChainCommunity* for the newly registered homeowner. The home-owners *BOBChainCommunity*, will look for the same *BOBChainCommunities* running elsewhere in the network and validate and obtain the chain. This chain will be stored locally.

### **OTA Interaction BOBChain**

Though an OTA is never registered as a member of the *BOBChainCommunity*, it is able to create transactions on the chain in the name of the homeowner. This allows the transactions happening on the chain to stay anonymous, seeing as all blocks created on the chain were done with the private and public key of the homeowner.

Each transaction pushed to the chain will be validated for both night-caps and overbookings, if the validation is approved the block will be appended to the chain. This will trigger the *BOBChainCommunity* to communicate to all other hosts running this specific home-owners BOBChainCommunity to either accept the block or deny it depending on if the validation process is accepted.

Allowing all OTAs to stay anonymous allows for the business sensitive information on the BOBChain to only be a rough sketch of the whole market instead of the output of individual OTAs bookings. Though this advantage restricts the use of *TrustChains* entanglement, seeing as all transactions on the chain are done only within one single party instead of between different parties.


### **Municipality Interaction BOBChain**

Functionality that is given to the municipality is allowing it to check the amount of nightcaps used per home and the total amount of bookings to a home. The right to disallow or revoke a license on the BOBChain is also possible.

The municipality is expected to run all *BOBChainCommunities*, this allows the municipality to play as a safe fail to ensure that data is not lost if networks go down. Though this means *BOBChain* entrusts the municipality to not interfere with bookings that are happening on the *BOBChain*.

### **Overview BOBChain Stakeholder Interaction**

![alt text](https://github.com/simionAndrei/BobChain/blob/master/images/arch.png "Stakeholder Architecture BOBChain")



---

## **How to make use of BOBChain**

To run the BOBChain as of ```16/01/2019 on ubuntu 18.04```
The following steps will need to be done:

Clone this repository with git with the following command:

```bash
git clone https://github.com/simionAndrei/BobChain.git pyipv8
```

Install the required dependencies for IPv8, these can be found in the ```requirements.txt``` file.

```bash
pip install --upgrade -r requirements.txt
```

Make sure that ```tkinter``` for python is installed:

```bash
sudo apt-get install python-tk
```

To get the GUI started and the IPv8 overlay ```python version 2``` must be used:

```bash
python2 main.py
```

This should launch the GUI interface an all interactions with the BOBChain can be done from there

---

## **Challenges that still need to be faced on POC: BOBChain.**

Within this section a discussion will be held about the current limitations of the BOBChain implementation. Suggestions will be made in how to tackle this limitations in future testing of the BOBChain infrastructure.

#### **Complete Decentralization**

With the current implementation of BOBChain and the network it will be running on means, a lot of trust is put into the municipality. The municipality has to be trusted to share all private and public keys to OTAs if a truthful request is done to gain access to a homeowners BOBChain. Secondly a large amount of trust is placed on the municipality to always run all the homeowners BOBChains to increase the risk of tampering with the BOBChains.

A solution to this problem would be to move the BOBChain to all participating parties. Thus homeowners would also need to run part of the network or soley their BOBChains. This would require trust and home-owners to be compliant to be continously running a service from their homes. This would disperse a lot of trust from the municipality and increase trustworhtyness in the BOBChain network.  

#### **BOBChain entanglement**

At the current time no entanglement is taking place when blocks are added to the chain. A timestamp is taken and is used to measure if a block can be added to the chain. This makes the validation of the chain straight forward but due to only one party part taking in the creation of the chain it loses entanglement.

Entanglement is a feature in TrustChain that allows for easy verification of blocks and ensuring that no manipulation has occured to the chain. Enabling the type of entanglement that TrustChain offers could be done in one of two ways:

The first way this could be achieved is by having the municipality and OTAs both join in the BOBChainCommuntie with their own BOBChain. This would mean for every booking an OTA does it could entangle its own BOBChain to the booking, though too keep anonymity  would be more challenging in this scenario.

The second solution would be having the previous booking transaction entangle the next bookings transaction. This would mean that OTAs would have to use a previous BOBChain to entangle the new booking. Depending on the amount of bookings happening this could cause throughput to slow down, as the state of each BOBChain would have to be continuously up-to-date. Though this may be only of minor concern.

The image belows shows how TrustChain entanglement looks like between blocks in the chain:
![alt text](https://github.com/simionAndrei/BobChain/blob/master/images/trustchain_engta.png "TustChain Entanglement")

#### **Dealing with Malicious OTAs**

Within the network all OTAs are trusted to not be malicious. Malicious behaviour like cancelling bookings, removing blocks from a chain are just some examples of the type of behaviour that is currently not monitored. With proper entanglement certain issues in malicious behaviour will be removed.

OTAs would have to come up with some set of policies they all agree on. Secondly after having a consensus on policies some type of system needs to be inplace to ensure malicious behaviour is not happening. One could envision a third-party or the municipality monitoring the behaviour happening on the BOBChain, though the monitoring party needs to be trustworthy.

Due to all parties being able to read the chain or parts of the chain, if malicious events are happening the OTAs could be able to see this in the chain. This could mean an investigation into the malicious events could take place.

#### **Business Model**

To bring this POC of BOBChain to production would require a capital investment. At this moment it is unsure where an investment would come from or even where it is invested in. One could envision a third-party company or some type of committee that is created between different OTAs and municipalities.

If a third-party company would bring forth a solution to this problem, they could be able to monitor and give a higher guarantee that all OTAs are playing by the rules. Though this party would have to be trusted by all parties involved.

If a committee was created between different OTAs to work on this problem together or entrust one OTA to create and manage the BOBCHain under the supervision of the other OTAs. This tool could be maintained by the biggest stakeholders in this technology. Though figuring out investment and agreements may be a difficult task.
