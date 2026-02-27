# Contributing to AgentMesh

Thank you for your interest in contributing to AgentMesh! We are building the foundational Trust Layer for AI Agents, and community contributions are essential to strengthening our governance platform.

## How to Contribute

1. **Report Bugs**: Use our Bug Report template to report reproducible issues.
2. **Suggest Features**: Help us map out new compliance standards or governance policies using the Feature Request template.
3. **Submit Pull Requests**: All PRs are welcome! Bug fixes, new policies, documentation updates, or framework integrations.

## Development Setup

We recommend using Python 3.10+ and a virtual environment.

```bash
git clone https://github.com/agentmesh/agentmesh.git
cd agentmesh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e "sdk/[dev]"
```

## Running Tests

We maintain a strict testing culture. All PRs must pass the test suite:

```bash
pytest
```

## Submitting a Pull Request

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-policy`).
3. Commit your changes.
4. Push to your branch (`git push origin feature/amazing-policy`).
5. Open a Pull Request and describe the changes in detail.

## Adding New Policies

If you are contributing a new policy to the Policy Engine:
- Ensure the policy logic goes into `sdk/src/agentmesh/cli/policies/`.
- Include standard policy metadata (ID, severity, description).
- Explain any EU AI Act mappings the policy fulfills.
- Add corresponding unit tests.

Welcome aboard! 🛡️
