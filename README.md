# **Booked on Blockchain, BOBChain**

BOBChain is an implemenation of a blockchain. The blockchain technology powering BOBChain is TrustChain created by Tribler at the Technical Univestity of Delft. 

The aim of this document is to give the reader insights into:

- Why BOBChain?
- Architecture of BOBChain.
- How to make use of BOBChain.
- Limitations of BOBChain.

---

### **Why BOBChain?** 

#### **The Problem:**

Globalization, budget airlines and the sharing economy have lead to an increase in the tourism market around the world. Highly popular touristic cities such as London, Paris, Amsterdam, etc. are experiencing a high influx of tourists. Due to the rise in tourism it has become profitable and exceedingly easy to out ones home too incoming tourists by services such as AirBnB. The increase in tourism and the rise in sharing economy, has lead to some cities to overflow. Causing grief to permanent residents of these cities.

Some of the effects of over-tourism are:

- Overcrowding of popular tourist attractions/areas
- Housing market prices SkyRocketing
- Permanent residence have issues with noise pollution
- Cities transportation infrastructure being overcrowded

Over-tourism has caused enough problems that municipality are taking notice and implementing laws to contest the ever growing increase of tourists. Some of these laws are looking at Online Travel Agencies (**OTAs**) to limit the amount of nightcaps residents are allowed to rent out their homes.  This should reduce the amount of homes bought to directly rent out to tourists due to it becoming less profitable.

The main issue with this enforcement is that OTAs do not have a platform where they can communicate with one another to see if residents, who are on multiple OTAs, are exceeding the nightcaps. At the moment OTAs can only internally check their service to see if a resident is exceeding nightcaps, allowing residents to use multiple OTA platforms to avoid such restrictions.

#### **Why blockchain?**

The rise in popularity of *blockchain technology* has been immense since cryptocurrencies like *bitcoin*, *Ethereum*, *Ripple*, etc. entered the attention of mainstream media outlets. Blockchain technology has also been implemented outside of being a currency, the rise of enterprise solutions like *Ethereum Smart-Contracts*, *HyperLedger*, *TrustChain*, etc.. Many different problems have been thrown at the new technology to see if it offers a viable solution.

Over-tourism in cities has led to municiplaties creating legal barries for home-owners with limiting the amount of nights a house can be rented out for. To ensure these limits are met municiplaties are putting increasing pressure and in-some cases legal consequences to OTAs to enforce these nightcaps on their customers/partners. 

OTAs have noticed the increase in legal consequences for having customers/partners exceed the legal nightcap limits of certain properties. Forseeing a future where OTAs must check when a booking is made that the home-owner has not exceeded his/her legal nightcap limit with other OTAs. Blockchain offers a unique solution to this problem, seeing as if API calls were made between platforms a worry exists that this may lead to cartel forming or be viewed as companies creating cartels. 

Having a decentralized way of checking if nightcap limits are not exceeded, allows for the OTAs to ensure the laws of the muncipality are being followed. Without having to worry that a cartel is being formed. Blockchain at first glance is the perfect solution for this problem. Since it allows for a decentralized ledger to be created, without having a central party control how it is run. 

#### **BOBChain Features**

**BOBChain** offers a blockchain solution to tackle the problem of legal nightcap limits that will allow current and future OTA to communicate on a decentralized ledger to ensure that no legal limits are exceeded. 

**BOBChain** offers a blockchain solution to tackle the dreaded overbooking, currently there is no central platform to check if an accomidation that is put up for rent on multiple OTA sites is double booked. The overbooking issue costs the OTAs money as an overbooking means they must usually refund or find a new accomdation for the booking customer. 

**BOBChain** offers a blockchain solution with authorized home-owner liscenses from muncipalities, these liscense can be shared by the homer-owner to different OTAs. The OTAs with these liscences can ensure no overbookings take place or nightcap limits are exceeded. 

**BOBChain** offers a blockchain solution that is decentralized and anonymous between the bookings of different OTA parties. Ensuring the privacy between different OTAs. Meaning no valuable business information is exchanged between OTAs.

---

## **Aritechture of BOBChain**

BOBChain is a direct extenstion of Triblers TrustChainCommunity; with some modifications to the validation of transactions and communications with other TrustChainCommunities. BOBChain's aritecture is centered around the idea that every home-owner gets a liscense and this liscense is seen as an accomidations private 'TrustChain' or in this case a 'BOBChain'. A design choice was made to have the municipality and OTAs run the TrustChainCommunities for the home-owners. Allowing BOBChain not to depend on home-owners keeping the service running but the municipality and OTAs.

To better describe the aritechture of BOBChain the process of how a home-owner is able to get a liscense, to authroize an OTA to use its liscense and how an OTA or Municipality can interact with the liscense. 

#### **Home-owner Attaining a Liscense** 

To ensure each home-owner is a private 'BOBChainCommunity', the home-owner must attain a liscense from the municiplality. The advantage of registering the home with the municipality is that the muncipality is able to monitor all the homes on the market. 

The creation of the private 'BOBChainCommunity' is done by generating a private and public key pair for the home-owner and storing it on local servers. The municipality will create a *genisis* block with the private and public key-pair of the home-owner, which will act as an agreement and a liscense for the home-owner. Too ensure that chains are kept up-to-date the municipality will have to continuously run all the 'BOBChainCommunities' and store there respective BOBChains in the database. 

#### **Home-owner Authorizing use of a Liscense**

Once a home-owner has registered his or her home, it can go to an OTA and authorize it to use it. This can either be done by registering the address by the OTA or giving the public-key the home-owner was given during the creation of the liscense. From here the OTA can request the private and public key pair to start the 'BOBChainCommunity'. 


Once a key pair has been acquired the OTA can start the 'BOBChainCommunity' for the newly regeistered home-owner. The home-owners 'BOBChainCommunity', will look for the same 'BOBChainCommunities' running elsewhere in the network and validate and obtain the chain. This chain will be stored locally. 

#### **OTA Interaction BOBChain**

Though an OTA is never registered as a memember of the 'BOBChainCommunity', it is able to create transactions on the chain in the name of the home-owner. This allows the transactions happening on the chain to stay annoymous, seeing as all blocks created on the chain were done with the private and public key of the home-owner. 

Each transaction pushed to the chain will be validated for both night-caps and overbookings, if the validation is approved the block will be appeneded to the chain. This will trigger the 'BOBChainCommunity' to communicate to all other hosts running this specific home-owners BOBChainCommunity to either accpet the block or deny it depending on if the validation process is accpeted. 

Allowing all OTAs to stay annoymous allows for the business sensitive information on the BOBChain to only be a rough sketch of the whole market instead of the output of individual OTAs bookings. Though this advantage restricts the use of TrustChain's entanglement, seeing as all transactions on the chain are done only within one single party instead of between different parties.


#### **Municipality Interaction BOBChain**

Functionality that is given to the municipality is allowing it to check the amount of nightcaps used per home and the total amount of bookings to a home. The right to disallow or revoke a liscense on the BOBChain is also possible. 

The municipality is expected to run all 'BOBChainCommunities', this allows the municipality to play as a safe fail to ensure that data is not lost if networks go down. Though this means 'BOBChain' entrusts the municipality to not interfer with bookings that are happening on the 'BOBChain'. 

---

## **How to make use of BOBChain**

To run the BOBChain as of 16/01/2019 on ubuntu 18.04
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