# my_PFE_SECDECOPA
MY PROJECT of study end is the secure version of the energy IOT protocol DECOPA (SECDECOPA)
📝 Table of Contents
Features
Tech Stack
File Structure
Getting Started
How to Use the Dashboard
Understanding the Interface
✨ Features
Interactive Simulation: Run simulations directly from the browser with the click of a button.
Customizable Parameters: Easily configure network size, simulation duration, energy levels, protocol behavior, and attack scenarios.
Comparative Analysis: Execute and compare the secure SECDCOPA against the non-secure Baseline DCOPA to evaluate performance differences.
Rich Data Visualization: View results through dynamic, zoomable, and pan-able charts that display:
Energy consumption over time.
Cluster dynamics (CH elections, join refusals).
Security events (malicious node exclusions).
Data integrity at the Base Station.
Live Console Log: Monitor the simulation's progress with real-time event logging.
Responsive Design: The dashboard is usable across desktop, tablet, and mobile devices.
🛠️ Tech Stack
Backend: Python 3, Flask
Frontend: HTML5, CSS3, Vanilla JavaScript
Charting Library: Chart.js with the chartjs-plugin-zoom for interactivity.
🗂️ File Structure
The project is organized into a standard Flask application structure:
code
Code
.
├── main.py             # Main Flask application: contains all backend logic, simulation code, and API routes.
├── static/
│   └── style.css       # CSS file for styling the dashboard interface.
└── templates/
    └── index.html      # The single HTML file that renders the entire user interface.
🚀 Getting Started
Follow these instructions to get the simulation dashboard running on your local machine.
Prerequisites
You must have Python 3 and pip (Python's package installer) installed on your system.
Installation & Running
Clone the repository:
code
Bash
git clone <your-repository-url>
cd <your-repository-name>
Create a virtual environment (Recommended):
This isolates the project's dependencies from your system's Python installation.
code
Bash
# On macOS/Linux
python3 -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
.\venv\Scripts\activate
Install the required package (Flask):
code
Bash
pip install Flask
Run the application:
code
Bash
python main.py
Access the Dashboard:
Open your web browser and navigate to the following address:
http://127.0.0.1:5000
💻 How to Use the Dashboard
Configure Parameters: Use the Configuration panel on the left to set up your simulation. You can adjust:
Network: Number of nodes, simulation rounds, initial energy.
Protocol: Cluster Head election probability, cluster capacity, trust threshold.
Security: The start and end rounds for the data falsification attack.
Run a Simulation: In the Controls section, click one of the buttons:
Run Baseline DECOPA: Executes the simulation with security features turned OFF.
Run SECDCOPA: Executes the simulation with security features turned ON.
Run & Compare: Runs both simulations back-to-back and displays their results side-by-side for easy comparison.
Analyze the Results: The results will be populated on the right-hand panel. Use the tabs to explore different aspects of the simulation data. You can zoom in on charts by scrolling with your mouse wheel and pan by clicking and dragging.
📊 Understanding the Interface
The results panel is divided into several sections:
Status Box: Shows the current state of the simulation (Idle, Running, Finished, or Error).
Live Console Log: Displays time-stamped logs from the backend, providing insights into the simulation's progress and key events.
Results Tabs:
Summary: A table providing the final, high-level metrics like Network Lifetime, Data Integrity, and Malicious Detection Time.
Cluster Dynamics & Security: Charts showing the number of elected Cluster Heads, join requests refused due to security checks, and malicious nodes excluded by SECDCOPA over time.
Energy Analysis: A line chart comparing the total energy consumed by the network in each simulation.
Data Integrity: A bar chart that visually contrasts the number of valid vs. falsified packets that reached the Base Station, clearly demonstrating SECDCOPA's effectiveness.
