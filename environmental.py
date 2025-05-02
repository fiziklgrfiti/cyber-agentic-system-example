#!/usr/bin/env python3
"""
Security Capability Measurement Program - Phase 1 Implementation
Milestone 1: Environment Setup

This module sets up the foundation for the message-based multi-agent system,
including LangChain and LangGraph configuration, logging, and monitoring.
"""

import os
import sys
import json
import time
import uuid
import logging
from typing import Dict, List, Any, Tuple, Optional, Union, Literal, TypedDict, Annotated
from enum import Enum
from datetime import datetime
from pathlib import Path

# LangChain imports
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.llms import Ollama

# LangGraph imports
from langgraph.graph import MessageGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

# Pydantic for validation
from pydantic import BaseModel, Field, validator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('security_measurement.log')
    ]
)
logger = logging.getLogger('security_measurement')

# Constants
DEFAULT_MODEL = "llama3.2:latest"  # Default Ollama model
DEFAULT_TEMPERATURE = 0.1  # Low temperature for more deterministic outputs
DEFAULT_CONFIG_PATH = "config/agents_config.json"
DEFAULT_DATA_DIR = "data"

# Create necessary directories
os.makedirs("config", exist_ok=True)
os.makedirs("data", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Message Types Enum
class MessageType(str, Enum):
    """Enumeration of message types for agent communication."""
    QUERY = "query"
    RESPONSE = "response"
    REQUEST = "request"
    NOTIFICATION = "notification"
    ERROR = "error"
    RESULT = "result"
    COMMAND = "command"
    STATUS = "status"


# Validation Models
class MessageContent(BaseModel):
    """Model for message content with metadata."""
    type: MessageType
    content: Any
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class AgentMessage(BaseModel):
    """Model for agent messages with routing information."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: str
    receiver: Optional[str] = None
    broadcast: bool = False
    content: MessageContent
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return self.model_dump()


class AgentConfig(BaseModel):
    """Configuration model for agent initialization."""
    agent_id: str
    agent_type: str
    description: str
    model_name: str = DEFAULT_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    system_prompt: Optional[str] = None
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    memory_config: Dict[str, Any] = Field(default_factory=dict)
    custom_config: Dict[str, Any] = Field(default_factory=dict)


class LLMManager:
    """
    Manages LLM instances and configurations.
    Provides a centralized way to create and reuse LLM instances.
    """
    
    def __init__(self):
        """Initialize the LLM manager."""
        self.llm_instances = {}
        logger.info("LLM Manager initialized")
    
    def get_llm(self, model_name: str = DEFAULT_MODEL, temperature: float = DEFAULT_TEMPERATURE) -> Any:
        """
        Get or create an LLM instance with the specified parameters.
        
        Args:
            model_name: Name of the model to use
            temperature: Temperature setting for the model
            
        Returns:
            LLM instance
        """
        key = f"{model_name}_{temperature}"
        
        if key not in self.llm_instances:
            logger.info(f"Creating new LLM instance: {model_name}, temp={temperature}")
            try:
                self.llm_instances[key] = Ollama(model=model_name, temperature=temperature)
            except Exception as e:
                logger.error(f"Error creating LLM instance: {str(e)}")
                raise
        
        return self.llm_instances[key]


class PerformanceMonitor:
    """
    Monitors and tracks performance metrics for the multi-agent system.
    """
    
    def __init__(self):
        """Initialize the performance monitor."""
        self.start_times = {}
        self.metrics = {
            "agent_latency": {},
            "llm_calls": 0,
            "llm_tokens": 0,
            "message_count": 0,
        }
        logger.info("Performance Monitor initialized")
    
    def start_timer(self, operation_id: str):
        """Start timing an operation."""
        self.start_times[operation_id] = time.time()
    
    def end_timer(self, operation_id: str, category: str):
        """
        End timing an operation and record the duration.
        
        Args:
            operation_id: ID of the operation being timed
            category: Category to record the metric under (e.g., agent ID)
        """
        if operation_id in self.start_times:
            duration = time.time() - self.start_times[operation_id]
            
            if category not in self.metrics["agent_latency"]:
                self.metrics["agent_latency"][category] = []
            
            self.metrics["agent_latency"][category].append(duration)
            del self.start_times[operation_id]
    
    def increment_llm_calls(self):
        """Increment the count of LLM API calls."""
        self.metrics["llm_calls"] += 1
    
    def add_tokens(self, count: int):
        """
        Add to the total token count.
        
        Args:
            count: Number of tokens to add
        """
        self.metrics["llm_tokens"] += count
    
    def increment_messages(self):
        """Increment the count of messages passed between agents."""
        self.metrics["message_count"] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get the current metrics.
        
        Returns:
            Dictionary of metrics
        """
        # Calculate averages for agent latencies
        avg_latencies = {}
        for agent, latencies in self.metrics["agent_latency"].items():
            if latencies:
                avg_latencies[agent] = sum(latencies) / len(latencies)
            else:
                avg_latencies[agent] = 0
        
        return {
            "agent_latency": avg_latencies,
            "llm_calls": self.metrics["llm_calls"],
            "llm_tokens": self.metrics["llm_tokens"],
            "message_count": self.metrics["message_count"],
        }
    
    def reset_metrics(self):
        """Reset all metrics."""
        self.metrics = {
            "agent_latency": {},
            "llm_calls": 0,
            "llm_tokens": 0,
            "message_count": 0,
        }
        self.start_times = {}


class ConfigManager:
    """
    Manages configuration loading and saving for the multi-agent system.
    """
    
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        logger.info(f"ConfigManager initialized with path: {config_path}")
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file or create default.
        
        Returns:
            Dictionary containing configuration
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config
            else:
                logger.info(f"Configuration file not found. Creating default configuration")
                # Create default configuration
                default_config = {
                    "agents": {
                        "coordinator": {
                            "agent_id": "coordinator",
                            "agent_type": "coordinator",
                            "description": "Coordinates workflow across all agents",
                            "model_name": DEFAULT_MODEL,
                            "temperature": DEFAULT_TEMPERATURE,
                            "system_prompt": "You are a coordinator agent that manages workflow across multiple specialized agents."
                        }
                    },
                    "workflow": {
                        "default_entry_point": "coordinator"
                    },
                    "settings": {
                        "default_model": DEFAULT_MODEL,
                        "default_temperature": DEFAULT_TEMPERATURE,
                        "data_directory": DEFAULT_DATA_DIR
                    }
                }
                
                # Save default configuration
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                return default_config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            # Return minimal working configuration
            return {
                "agents": {},
                "workflow": {"default_entry_point": "coordinator"},
                "settings": {
                    "default_model": DEFAULT_MODEL,
                    "default_temperature": DEFAULT_TEMPERATURE,
                    "data_directory": DEFAULT_DATA_DIR
                }
            }
    
    def get_agent_config(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a specific agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            Agent configuration or None if not found
        """
        return self.config.get("agents", {}).get(agent_id)
    
    def get_all_agent_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        Get configuration for all agents.
        
        Returns:
            Dictionary of agent configurations
        """
        return self.config.get("agents", {})
    
    def save_agent_config(self, agent_id: str, config: Dict[str, Any]):
        """
        Save configuration for a specific agent.
        
        Args:
            agent_id: ID of the agent
            config: Agent configuration
        """
        if "agents" not in self.config:
            self.config["agents"] = {}
        
        self.config["agents"][agent_id] = config
        
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        logger.info(f"Saved configuration for agent: {agent_id}")
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a setting from the configuration.
        
        Args:
            key: Setting key
            default: Default value if setting not found
            
        Returns:
            Setting value or default
        """
        return self.config.get("settings", {}).get(key, default)
    
    def set_setting(self, key: str, value: Any):
        """
        Set a setting in the configuration.
        
        Args:
            key: Setting key
            value: Setting value
        """
        if "settings" not in self.config:
            self.config["settings"] = {}
        
        self.config["settings"][key] = value
        
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        logger.info(f"Updated setting: {key}={value}")


class TestFramework:
    """
    Basic testing framework for validating agent functionality.
    """
    
    def __init__(self):
        """Initialize the test framework."""
        self.test_results = {}
        logger.info("Test Framework initialized")
    
    def run_test(self, test_name: str, test_function, *args, **kwargs) -> bool:
        """
        Run a test function and record the result.
        
        Args:
            test_name: Name of the test
            test_function: Function to execute
            args: Arguments to pass to the test function
            kwargs: Keyword arguments to pass to the test function
            
        Returns:
            Boolean indicating test success
        """
        logger.info(f"Running test: {test_name}")
        start_time = time.time()
        
        try:
            result = test_function(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
            logger.error(f"Test failed: {test_name} - {error}")
        
        duration = time.time() - start_time
        
        self.test_results[test_name] = {
            "success": success,
            "duration": duration,
            "error": error,
            "timestamp": datetime.now().isoformat()
        }
        
        if success:
            logger.info(f"Test passed: {test_name} in {duration:.2f}s")
        
        return success
    
    def get_test_results(self) -> Dict[str, Any]:
        """
        Get all test results.
        
        Returns:
            Dictionary of test results
        """
        return self.test_results


# Initialize global instances
llm_manager = LLMManager()
performance_monitor = PerformanceMonitor()
config_manager = ConfigManager()
test_framework = TestFramework()

# Run basic tests to validate environment setup
def test_llm_availability():
    """Test that the LLM is available and responding."""
    llm = llm_manager.get_llm()
    response = llm.invoke("Hello, are you working?")
    return len(response) > 0

def test_config_save_load():
    """Test that configuration can be saved and loaded."""
    test_agent_id = "test_agent"
    test_config = {
        "agent_id": test_agent_id,
        "agent_type": "test",
        "description": "Test agent for validation",
        "model_name": DEFAULT_MODEL
    }
    
    config_manager.save_agent_config(test_agent_id, test_config)
    loaded_config = config_manager.get_agent_config(test_agent_id)
    
    return loaded_config == test_config

# Validate the environment setup
if __name__ == "__main__":
    logger.info("Running environment validation tests")
    
    # Test LLM availability
    llm_available = test_framework.run_test("llm_availability", test_llm_availability)
    
    # Test configuration management
    config_working = test_framework.run_test("config_save_load", test_config_save_load)
    
    # Report results
    all_tests_passed = all(result["success"] for result in test_framework.get_test_results().values())
    
    if all_tests_passed:
        logger.info("Environment setup validated successfully!")
        print("✅ Environment setup validated successfully!")
    else:
        logger.error("Environment setup validation failed. Check logs for details.")
        print("❌ Environment setup validation failed. Check logs for details.")
        
    # Print test results summary
    print("\nTest Results Summary:")
    for name, result in test_framework.get_test_results().items():
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        print(f"{status} - {name} ({result['duration']:.2f}s)")
        if not result["success"] and result["error"]:
            print(f"  Error: {result['error']}")
    
    print("\nEnvironment setup complete.")