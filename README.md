# Falcon Auto IoC
## Introduction
Well, folks, if you've stumbled upon this little corner of the internet, chances are you're looking to dive into the world of 
malware data without getting your hands too dirty. 
Lucky for you, we've got a Python script that'll fetch malware hashes like it's picking apples in an orchard...except these apples bite back.

## Installation
Now, installing this script is easier than forgetting your ex's birthday. 

But just in case you're the type who needs a roadmap to get out of a paper bag, here's how you do it:

### Step 1: Clone the Repository
First things first, let's get this show on the road. Open up your terminal...you know, that black box where magic happens...and run:

```bash
git clone https://github.com/QbDVision-Inc/Falcon-Auto-IoC.git
cd Falcon-Auto-IoC
```

### Step 2: Set Up a Python Virtual Environment
Because isolating problems is the first step to solving them, or so my therapist says, we're gonna set up a virtual environment. 

Think of it as a playpen for your Python packages.
```bash
python3 -m venv venv
```

Activate the virtual environment:

* On Unix or MacOS:
```bash
source venv/bin/activate
```

* On Windows:
```bash
venv\Scripts\activate
```

### Step 3: Install Dependencies
Now, let's install the necessary packages. 

Without these, the script is about as useful as a chocolate teapot.

```bash
pip install -r requirements.txt
```

If you see a bunch of text flying by, that's good. It means stuff is happening.

### Configuration
Before you run the script, you need to set up the `sources.yaml` file. 

Don't worry..it's easier than assembling IKEA furniture.
#### Step 1: Create the sources.yaml File

Just rename `sources.example.yaml` to `sources.yaml` and fill in the blank !

##### Explaination

* **sources**: A list of URLs where the script will fetch malware data. Feel free to add more if you're feeling adventurous.
* **client_id**: Your CrowdStrike Falcon API client_id. Replace YOUR_CLIENT_ID_HERE with your actual client_id.
* **client_secret**: Your CrowdStrike Falcon API client_secret. Replace YOUR_CLIENT_SECRET_HERE with your actual client_secret.
* **falcon_base_url**: The base URL for the Falcon API. Unless you're in a parallel universe, this should be `https://api.[region].crowdstrike.com`.

### Step 3: Keep Your Credentials Safe
Seriously, don't go sharing your client_id and client_secret on social media, git or tattooing them on your arm. Keep this file secure.

### Usage
Alright, you've made it this far without breaking anything, kudos to you ! Time to run the script:

```bash
python main.py
```

You'll be greeted with:

```bash
Do you want to download data for the last 15 days? (yes/no):
```

Type **yes** if you're feeling adventurous, or **no** if patience isn't your virtue.

### What Happens Next?
* **Progress Bar**: You'll see a progress bar because waiting without visuals is just cruel.
* **Data Fetching**: The script fetches malware data for the selected date range. It's like fishing, but you're catching the stuff nightmares are made of.
* **Processing**: It processes the data, extracts useful information, and pretends it did all the hard work.
* **Duplicate Removal**: It removes duplicates because nobody likes reruns—unless it's that one episode of your favorite show.
* **CSV Generation**: Finally, it spits out an output.csv file with all the malware data neatly organized, so you can feel like a cybersecurity superhero.

#### New Feature Alert: Automatic Upload to Falcon API
But wait, there's more! After the CSV file is generated, the script will ask:
```bash
Do you want to send each record via POST request to Falcon API? (yes/no):
```

Type **yes** if you want the script to automatically upload the IoCs to your Falcon instance. The script will then:
* Obtain an OAuth2 access token using your client_id and client_secret.
* Send each indicator to the Falcon API with proper authentication.
* Handle any errors along the way because nothing's perfect

#### Important Notes:
* **Falcon API Credentials**: Make sure your client_id and client_secret are correct in the sources.yaml file.
* **Falcon Base URL**: Ensure the falcon_base_url is correct. If you're not sure, check crowdstrike documentation
* **Internet Connection**: Obviously, you need an internet connection. This script isn't psychic.

### Manual Upload to Falcon (Optional)
If you chose no when asked to send data to the Falcon API, you can still manually upload the output.csv. Here's how:

1. Login into your Falcon instance.
2. Navigate to Endpoint Security.
3. Go to IOC Management.
4. Choose Import with Metadata.
5. Select the output.csv file.
6. And voilà!

## What's Under the Hood?
### Multiple Data Sources
The script now supports multiple data sources defined in the sources.yaml file. No more hardcoded URLs—flexibility is the name of the game.

### Smarter Data Processing
* **IP Addresses and Ports**: It handles ip-dst|port types by extracting the IP address and assigning it the correct type (ipv4 or ipv6).
* **URLs and Domains**: For url types, it extracts the domain and assigns it accordingly.
* **Intelligent Type Assignment**: It checks if a domain is actually an IP address and assigns the correct type because who needs more confusion?

### OAuth2 Authentication
* **Access Token Retrieval**: The script fetches an access token using OAuth2, complying with Falcon's updated authentication methods.
* **Secure API Calls**: Uses the access token to authenticate API requests when sending IoCs to Falcon.

## Roadmap
Just like my uncle always says, "If you ain't moving forward, you're standing still." 
Here's what's on the horizon for this script:

1. **Handling Even More Data Sources**
Why settle for two sources of malware data when you can have many? We're planning to make this script fetch data from other places too. It's becoming quite the social butterfly.

2. **Better Platform Selection**
Right now, it's by default Windows, Mac, and Linux. 
In the future, we'll give you the option to pick and choose platforms—because customization is the spice of life.

3. **Enhanced Error Handling**
Because nobody likes cryptic error messages. We'll make the script smarter at telling you what's wrong in plain English (or whatever language you prefer).

## Conclusion
Well, that's all she wrote. If you run into any issues, feel free to open an issue on GitHub. We'll get to it faster than a toupee in a hurricane.

Happy malware hunting!

---------------------------
_Disclaimer: Use this script responsibly. And remember, with great power comes great responsibility—or at least that's what they told me before I broke the coffee machine._