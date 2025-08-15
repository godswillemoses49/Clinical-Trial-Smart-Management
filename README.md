# 🔬 Clinical Trial Smart Management

A Clarity smart contract for managing clinical trials on the Stacks blockchain.

## 🌟 Features

- ✅ Trial creation and management
- 🤝 Participant consent tracking
- 📊 Data collection and validation
- 💰 Milestone-based funding release
- 🔒 Privacy and security controls

## 📋 Contract Overview

This smart contract provides a comprehensive system for managing clinical trials with the following components:

- **Trial Management**: Create and update clinical trials with detailed information
- **Participant Enrollment**: Enroll participants and track their consent status
- **Data Collection**: Securely record and validate trial data
- **Funding Management**: Release funding based on completed milestones

## 🚀 Getting Started

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Basic knowledge of Clarity and Stacks blockchain

### Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/clinical-trial-smart-management.git
```

2. Navigate to the project directory:
```bash
cd clinical-trial-smart-management
```

3. Test the contract using Clarinet:
```bash
clarinet test
```

## 📖 Usage Examples

### Creating a New Trial

```clarity
(contract-call? .clinical-trial create-trial "COVID-19 Vaccine Trial" "Phase 3 trial for COVID-19 vaccine" u1000000 u100 u500)
```

### Enrolling a Participant

```clarity
(contract-call? .clinical-trial enroll-participant u1 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
```

### Giving Consent (as a participant)

```clarity
(contract-call? .clinical-trial give-consent u1)
```

### Adding Data Points

```clarity
(contract-call? .clinical-trial add-data-point u1 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 0x8a9c5031c5ecaad54134f7ae559e91192d52d0b5c8c409c410d41d3c79ae2a29)
```

### Creating and Completing Milestones

```clarity
(contract-call? .clinical-trial add-milestone u1 "50% Enrollment Complete" u250000)
(contract-call? .clinical-trial complete-milestone u1 u1)
```

## 🔍 Contract Functions

### Trial Management
- `create-trial`: Create a new clinical trial
- `update-trial-status`: Update the status of a trial

### Participant Management
- `enroll-participant`: Add a participant to a trial
- `give-consent`: Record participant consent
- `withdraw-consent`: Record participant withdrawal

### Data Management
- `add-data-point`: Add clinical data for a participant
- `validate-data-point`: Validate collected data

### Funding Management
- `add-milestone`: Create a funding milestone
- `complete-milestone`: Mark a milestone as complete and release funds

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
```

