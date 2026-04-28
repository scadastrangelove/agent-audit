"""Unit tests for knowledge/agent_task_adapter.py (D-9)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.agent_task_adapter import (  # noqa: E402
    is_agent_task_config, extract_instruction_text,
)


def _write_yaml(text: str) -> Path:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    f.write(text)
    f.close()
    return Path(f.name)


def test_agentverse_style_matches():
    """Real AgentVerse task config shape (simplified)."""
    text = """prompts:
  prompt: |-
    Now you are act as an agent in a virtual world.
    You have these actions available:
    - do_nothing() means do nothing and stick to current plan
    - act(description, target=None) performs an action
    - say(content, target=None) speaks to another agent

name: test_task
environment:
  env_type: reflection
  max_turns: 30

agents:
  - agent_type: conversation
    role_description: Alice is a teacher in the school
    prompt: Follow the agent instructions above
"""
    p = _write_yaml(text)
    assert is_agent_task_config(p), "AgentVerse-style config must match"
    extracted = extract_instruction_text(p)
    assert "virtual world" in extracted
    assert "do_nothing" in extracted
    # role_description was short (<40 chars), filter excludes. Instead verify
    # the instruction string we know is long.
    assert "say(content" in extracted or "act(description" in extracted
    print("  ✓ AgentVerse-style config matches")


def test_docker_compose_rejected():
    text = """version: '3'
services:
  web:
    image: nginx
    ports:
      - "80:80"
    environment:
      - NODE_ENV=production
"""
    p = _write_yaml(text)
    assert not is_agent_task_config(p), "docker-compose must not match"
    print("  ✓ docker-compose rejected")


def test_generic_agents_list_rejected():
    """Bare 'agents: [alice, bob]' has no prompt fields — not a task config."""
    text = """agents:
  - alice
  - bob
"""
    p = _write_yaml(text)
    assert not is_agent_task_config(p), "Generic agent list without prompts must not match"
    print("  ✓ Generic agent list without prompts rejected")


def test_gha_workflow_rejected():
    """GitHub Actions workflow yaml — false positive risk."""
    text = """name: CI
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: pytest
"""
    p = _write_yaml(text)
    assert not is_agent_task_config(p), "GHA workflow must not match"
    print("  ✓ GitHub Actions workflow rejected")


def test_pyproject_style_rejected():
    """Python package metadata — must not match."""
    text = """[project]
name = "my-package"
version = "1.0"
"""
    p = _write_yaml(text)
    # This is TOML syntax, loaded as yaml it produces garbage — gate should reject
    assert not is_agent_task_config(p), "Non-yaml content must not match"
    print("  ✓ Non-yaml content (loaded as yaml) rejected")


def test_autogen_style_matches():
    """AutoGen-like multi-agent config."""
    text = """name: research_crew
task_description: Research and summarize quantum computing papers

agents:
  - name: researcher
    system_message: You are a research assistant. Find papers and summarize key findings.
    description: Reads academic databases
  - name: critic
    system_message: You are a critic. Review summaries for accuracy and depth.

max_rounds: 10
"""
    p = _write_yaml(text)
    assert is_agent_task_config(p), "AutoGen-style config must match"
    extracted = extract_instruction_text(p)
    assert "research assistant" in extracted.lower()
    assert "critic" in extracted.lower()
    print("  ✓ AutoGen-style config matches")


def test_crewai_style_matches():
    """CrewAI-like agent definition."""
    text = """agents:
  researcher:
    role: Senior Research Analyst at a leading technology company
    goal: Uncover cutting-edge developments in AI and machine learning trends
    backstory: You are a seasoned researcher with 20 years of experience in the field
    tools:
      - search_tool
      - web_scraper

tools:
  - name: search_tool
    description: Google search API for web queries and information retrieval
"""
    p = _write_yaml(text)
    assert is_agent_task_config(p), "CrewAI-style config must match"
    extracted = extract_instruction_text(p)
    assert "cutting-edge developments" in extracted
    assert "seasoned researcher" in extracted
    print("  ✓ CrewAI-style config matches")


def test_extract_returns_empty_for_non_matches():
    """Non-matching file should extract to empty text."""
    text = "version: '3'\nservices:\n  db:\n    image: postgres\n"
    p = _write_yaml(text)
    result = extract_instruction_text(p)
    # Either empty or only short strings; should not contain ns/postgres as prompt
    assert "postgres" not in result or len(result) < 20
    print("  ✓ extract empty for non-matches")


def test_invalid_yaml_rejected():
    """Malformed YAML should return False / empty without crashing."""
    text = "invalid: {{{ broken yaml }}}\nagents: [\n"
    p = _write_yaml(text)
    assert not is_agent_task_config(p)
    assert extract_instruction_text(p) == ""
    print("  ✓ invalid YAML rejected without crash")


def test_non_yaml_extension_rejected():
    """Only .yaml/.yml files are candidates."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    f.write("agents: [alice]\nprompt: hello world\n")
    f.close()
    p = Path(f.name)
    assert not is_agent_task_config(p), "Non-yaml extension must be rejected"
    print("  ✓ Non-yaml extension rejected")


def run_all():
    tests = [
        test_agentverse_style_matches,
        test_docker_compose_rejected,
        test_generic_agents_list_rejected,
        test_gha_workflow_rejected,
        test_pyproject_style_rejected,
        test_autogen_style_matches,
        test_crewai_style_matches,
        test_extract_returns_empty_for_non_matches,
        test_invalid_yaml_rejected,
        test_non_yaml_extension_rejected,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: {e}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"Passed: {passed}/{len(tests)}")
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    run_all()
