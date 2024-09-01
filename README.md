# ND_MAC Project

## Overview

This project implements a robust Message Authentication Code (MAC) generator and checker system. It consists of two primary classes: `MACGenerator` and `MACChecker`. The `MACGenerator` class is responsible for generating HMACs for packets in a `Page`, while the `MACChecker` class verifies the integrity of those packets. The system supports filling in missing packets and calculating message latencies.

## Project Structure

The project is organized as follows:


- **ND_MAC/**
  - **Book (submodule)**
  - **src/**
    - `__pycache__/`
    - **tests/**
      - `__init__.py`
      - `nDMAC_test.py`
    - `__init__.py`
    - `nD_MAC.py`
  - `LICENSE`
  - `README.md`
  - `Example.ipynb`


- Book/: Contains the `Packet` and `Page` classes.
- src/: Contains the main implementation (`nD_MAC.py`) and the unit tests (`tests/nDMAC_test.py`).
- Example.ipynb: A Jupyter notebook demonstrating the usage of the `MACGenerator` and `MACChecker` classes.

## Installation

1. Clone the repository:

   `git clone https://github.com/your-username/ND_MAC.git`

   `cd ND_MAC`


2. Install dependencies:

   Install the required Python packages using pip.

   `pip install -r requirements.txt`  (Create this file if it doesn't exist)

## Usage

1. MAC Generation:

   Use the `MACGenerator` class to generate MACs for the packets in a `Page`.

2. MAC Verification:

   Use the `MACChecker` class to verify the integrity of the packets and calculate message latencies.

### Example

You can find an example of how to use these classes in `Example.ipynb`.

## Running Unit Tests

To ensure everything is working correctly, you can run the provided unit tests.

1. Navigate to the `src` directory:

   `cd src`

2. Run the tests:

   `python3 -m unittest discover -s src/tests`

   Alternatively, you can run a specific test file:

   `python3 -m unittest src/tests.nDMAC_test`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributions

Contributions are welcome! Please feel free to submit a Pull Request or open an issue if you find a bug or have a feature request.

## Contact

For any questions or issues, please contact [mkashani.phd@gmail.com].
