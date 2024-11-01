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

Once you have your `output.csv` all you have to do is:
1. Login into your Falcon instance
2. Endpoint Security
3. IOC Management
4. Import with Metadata

and voilà !

## Roadmap
Just like my uncle always says, "If you ain't moving forward, you're standing still." Here's what's on the horizon for this script:

1. **Automatic Upload into Falcon**

We're working on teaching this script to automatically upload data into Falcon. Soon, it'll be more connected than a teenager's social media.

2. **Handling More Different Sources**

Why settle for one source of malware data when you can have many? We're planning to make this script fetch data from other places too. It's becoming quite the social butterfly.

3. **Better Selections in Which Platforms Are Affected**

Right now, we're covering Windows, Mac, and Linux like a blanket covers a bed. In the future, we'll give you the option to pick and choose platforms—because customization is the spice of life.

## Conclusion
Well, that's all she wrote. If you run into any issues, feel free to open an issue on GitHub. We'll get to it faster than a toupee in a hurricane.

Happy malware hunting!

---------------------------
_Disclaimer: Use this script responsibly. And remember, with great power comes great responsibility—or at least that's what they told me before I broke the coffee machine._