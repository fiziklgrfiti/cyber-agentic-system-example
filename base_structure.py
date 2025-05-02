#!/usr/bin/env python3
"""
Security Capability Measurement Program - Phase 1 Implementation
Milestone 2: Core Agent Framework - Base Structure

This module implements the core agent framework with message-based
architecture, including the base agent class, agent registry,
and message handling capabilities.

Version marker: 2025-05-02-001
"""

import os
import sys
import time
import json
import uuid
import logging
import inspect
import importlib
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Tuple, Optional, Union, Callable, Type, Set
from datetime import datetime
from contextlib import contextmanager

# Import shared components from Milestone 1
try:
    from environmental import (
        MessageType, MessageContent, AgentMessage, AgentConfig,
        LLMManager, PerformanceMonitor, ConfigManager, 
        logger, DEFAULT_MODEL, DEFAULT_TEMPERATURE
    )
except ImportError:
    # For standalone testing
    from typing import TypedDict, Annotated
    from enum import Enum
    from pydantic import BaseModel, Field

    # LangChain imports
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_community.llms import Ollama

    # LangGraph imports
    from langgraph.graph import MessageGraph, END
    from langgraph.prebuilt import ToolNode
    from langgraph.checkpoint.memory import MemorySaver

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
    DEFAULT_MODEL = "llama3.2:latest"
    DEFAULT_TEMPERATURE = 0.1

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
        DEFAULT = "default"  # For default handlers
        REPORTS_COMMAND = "reports_command"  # For report commands

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

    # Simplified versions of the manager classes for standalone testing
    class LLMManager:
        def __init__(self):
            self.llm_instances = {}
        
        def get_llm(self, model_name=DEFAULT_MODEL, temperature=DEFAULT_TEMPERATURE):
            return Ollama(model=model_name, temperature=temperature)

    class PerformanceMonitor:
        def __init__(self):
            self.start_times = {}
            self.metrics = {"agent_latency": {}, "llm_calls": 0}
        
        def start_timer(self, operation_id):
            self.start_times[operation_id] = time.time()
        
        def end_timer(self, operation_id, category):
            if operation_id in self.start_times:
                duration = time.time() - self.start_times[operation_id]
                if category not in self.metrics["agent_latency"]:
                    self.metrics["agent_latency"][category] = []
                self.metrics["agent_latency"][category].append(duration)
                del self.start_times[operation_id]
        
        def increment_llm_calls(self):
            self.metrics["llm_calls"] += 1

    class ConfigManager:
        def __init__(self, config_path="config/agents_config.json"):
            self.config_path = config_path
            self.config = {"agents": {}, "settings": {}}
        
        def get_agent_config(self, agent_id):
            return self.config.get("agents", {}).get(agent_id)
        
        def save_agent_config(self, agent_id, config):
            if "agents" not in self.config:
                self.config["agents"] = {}
            self.config["agents"][agent_id] = config


# Global instances for standalone testing, would be imported from milestone1 normally
llm_manager = LLMManager()
performance_monitor = PerformanceMonitor()
config_manager = ConfigManager()


class MessageBus:
    """
    MessageBus handles message routing between agents in the system.
    It maintains subscriptions and handles broadcasting.
    """
    
    def __init__(self):
        """Initialize the message bus."""
        self.subscribers = {}  # topic -> set of agent_ids
        self.direct_routes = {}  # agent_id -> queue of messages
        self.broadcast_history = {}  # topic -> list of last N messages
        self.history_limit = 100  # Maximum number of messages to keep in history
        self.message_counter = 0
        logger.info("MessageBus initialized")
    
    def subscribe(self, agent_id: str, topics: List[str] = None):
        """
        Subscribe an agent to one or more topics.
        
        Args:
            agent_id: ID of the agent subscribing
            topics: List of topics to subscribe to (None for all topics)
        """
        if topics is None:
            # Subscribe to all messages (wildcard)
            if "*" not in self.subscribers:
                self.subscribers["*"] = set()
            self.subscribers["*"].add(agent_id)
            logger.debug(f"Agent {agent_id} subscribed to all topics")
        else:
            for topic in topics:
                if topic not in self.subscribers:
                    self.subscribers[topic] = set()
                self.subscribers[topic].add(agent_id)
                logger.debug(f"Agent {agent_id} subscribed to topic {topic}")
            """
            Subscribe an agent to one or more topics.
            
            Args:
                agent_id: ID of the agent subscribing
                topics: List of topics to subscribe to (None for all topics)
            """
            if topics is None:
                # Subscribe to all messages (wildcard)
                if "*" not in self.subscribers:
                    self.subscribers["*"] = set()
                self.subscribers["*"].add(agent_id)
                logger.debug(f"Agent {agent_id} subscribed to all topics")
            else:
                for topic in topics:
                    if topic not in self.subscribers:
                        self.subscribers[topic] = set()
                    self.subscribers[topic].add(agent_id)
                    logger.debug(f"Agent {agent_id} subscribed to topic {topic}")
    
    def unsubscribe(self, agent_id: str, topics: List[str] = None):
        """
        Unsubscribe an agent from one or more topics.
        
        Args:
            agent_id: ID of the agent unsubscribing
            topics: List of topics to unsubscribe from (None for all topics)
        """
        if topics is None:
            # Unsubscribe from all topics
            for topic, subscribers in self.subscribers.items():
                if agent_id in subscribers:
                    subscribers.remove(agent_id)
            logger.debug(f"Agent {agent_id} unsubscribed from all topics")
        else:
            for topic in topics:
                if topic in self.subscribers and agent_id in self.subscribers[topic]:
                    self.subscribers[topic].remove(agent_id)
                    logger.debug(f"Agent {agent_id} unsubscribed from topic {topic}")
    
    def send_message(self, message: AgentMessage) -> bool:
        """
        Send a message to its intended recipients.
        
        Args:
            message: Message to send
            
        Returns:
            Boolean indicating success
        """
        self.message_counter += 1
        
        # Handle broadcast messages
        if message.broadcast:
            return self._broadcast_message(message)
        
        # Handle direct messages
        if message.receiver:
            if message.receiver not in self.direct_routes:
                self.direct_routes[message.receiver] = []
            
            self.direct_routes[message.receiver].append(message)
            logger.debug(f"Message from {message.sender} routed to {message.receiver}")
            return True
        
        # If no receiver and not broadcast, treat as an error
        logger.warning(f"Message from {message.sender} has no receiver and is not broadcast")
        return False
    
    def _broadcast_message(self, message: AgentMessage) -> bool:
        """
        Broadcast a message to all subscribers of its type.
        
        Args:
            message: Message to broadcast
            
        Returns:
            Boolean indicating success
        """
        message_type = message.content.type
        
        # Store in broadcast history
        if message_type not in self.broadcast_history:
            self.broadcast_history[message_type] = []
        
        history = self.broadcast_history[message_type]
        history.append(message)
        
        # Truncate history if needed
        if len(history) > self.history_limit:
            self.broadcast_history[message_type] = history[-self.history_limit:]
        
        # Determine recipients
        recipients = set()
        
        # Add subscribers to this specific message type
        if message_type.value in self.subscribers:
            recipients.update(self.subscribers[message_type.value])
        
        # Add subscribers to all messages
        if "*" in self.subscribers:
            recipients.update(self.subscribers["*"])
        
        # Remove the sender from recipients
        if message.sender in recipients:
            recipients.remove(message.sender)
        
        # Queue message for all recipients
        for recipient in recipients:
            if recipient not in self.direct_routes:
                self.direct_routes[recipient] = []
            
            self.direct_routes[recipient].append(message)
        
        logger.debug(f"Broadcast message from {message.sender} of type {message_type} routed to {len(recipients)} recipients")
        return True

    def get_messages(self, agent_id: str) -> List[AgentMessage]:
        """
        Get all pending messages for an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            List of messages for the agent
        """
        if agent_id not in self.direct_routes:
            return []
        
        messages = self.direct_routes[agent_id]
        self.direct_routes[agent_id] = []  # Clear the queue
        
        return messages
    
    def get_broadcast_history(self, message_type: MessageType, limit: int = None) -> List[AgentMessage]:
        """
        Get broadcast history for a specific message type.
        
        Args:
            message_type: Type of messages to retrieve
            limit: Maximum number of messages to retrieve
            
        Returns:
            List of broadcast messages
        """
        if message_type not in self.broadcast_history:
            return []
        
        history = self.broadcast_history[message_type]
        
        if limit is not None:
            return history[-limit:]
        
        return history.copy()
    
    def get_message_count(self) -> int:
        """
        Get the total number of messages processed.
        
        Returns:
            Message count
        """
        return self.message_counter


class BaseAgent(ABC):
    """
    Base class for all agents in the system.
    Handles message processing and provides common functionality.
    """
    
    def __init__(self, agent_id: str, agent_type: str, description: str, message_bus: MessageBus,
             model_name: str = DEFAULT_MODEL, temperature: float = DEFAULT_TEMPERATURE,
             system_prompt: str = None, system=None):
        """
        Initialize the base agent.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_type: Type of agent (e.g., coordinator, inventory)
            description: Description of the agent's purpose
            message_bus: MessageBus for communication
            model_name: Name of the LLM model to use
            temperature: Temperature setting for the LLM
            system_prompt: System prompt for the LLM
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.description = description
        self.message_bus = message_bus
        self.model_name = model_name
        self.temperature = temperature
        self.system_prompt = system_prompt or self._get_default_system_prompt()
        
        self.llm = llm_manager.get_llm(model_name, temperature)
        self.message_handlers = self._register_message_handlers()
        self.memory = {}  # Simple memory store
        
        # Store system reference
        self.system = system
        
        # Subscribe to direct messages
        self.message_bus.subscribe(self.agent_id)
        
        logger.info(f"Agent {self.agent_id} ({self.agent_type}) initialized")
    
    def _get_default_system_prompt(self) -> str:
        """
        Get the default system prompt for this agent type.
        
        Returns:
            Default system prompt
        """
        return f"You are a {self.agent_type} agent with ID {self.agent_id}. {self.description}"
    
    def _register_message_handlers(self) -> Dict[MessageType, Callable]:
        """
        Register message handlers for different message types.
        
        Returns:
            Dictionary mapping message types to handler functions
        """
        handlers = {}
        
        # Find all methods that start with 'handle_'
        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if name.startswith("handle_") and len(name) > 7:
                message_type_name = name[7:].upper()  # Extract message type name
                
                # Try to convert 'default' to MessageType.DEFAULT, etc.
                try:
                    message_type = MessageType[message_type_name]
                    handlers[message_type] = method
                    logger.debug(f"Registered handler {name} for message type {message_type.value}")
                except KeyError:
                    # The handler doesn't match any MessageType
                    # Instead of warning, we'll log a debug message
                    logger.debug(f"Custom handler {name} found but not registered to a standard MessageType")
        
        return handlers
    
    def process_messages(self):
        """Process all pending messages for this agent."""
        messages = self.message_bus.get_messages(self.agent_id)
        
        for message in messages:
            self.process_message(message)
    
    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Process a single message.
        
        Args:
            message: Message to process
            
        Returns:
            Optional response message
        """
        operation_id = f"{message.id}_{self.agent_id}"
        performance_monitor.start_timer(operation_id)
        
        try:
            message_type = message.content.type
            
            # Check if we have a handler for this message type
            if message_type in self.message_handlers:
                handler = self.message_handlers[message_type]
                response = handler(message)
            else:
                # Default handler for unregistered message types
                response = self.handle_default(message)
            
            performance_monitor.end_timer(operation_id, self.agent_id)
            return response
            
        except Exception as e:
            logger.error(f"Error processing message in agent {self.agent_id}: {str(e)}")
            performance_monitor.end_timer(operation_id, self.agent_id)
            
            # Send error message back to sender
            return self.create_error_message(
                f"Error processing message: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def handle_default(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Default handler for message types without a specific handler.
        
        Args:
            message: Message to handle
            
        Returns:
            Optional response message
        """
        logger.warning(f"No handler for message type {message.content.type} in agent {self.agent_id}")
        return None
    
    def handle_error(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle error messages.
        
        Args:
            message: Error message to handle
            
        Returns:
            Optional response message
        """
        logger.error(f"Agent {self.agent_id} received error: {message.content.content}")
        return None
    
    def create_message(self, content: Any, message_type: MessageType, 
                      receiver: str = None, broadcast: bool = False,
                      metadata: Dict[str, Any] = None, reply_to: str = None) -> AgentMessage:
        """
        Create a new message.
        
        Args:
            content: Message content
            message_type: Type of message
            receiver: Recipient agent ID
            broadcast: Whether to broadcast the message
            metadata: Additional metadata
            reply_to: ID of message being replied to
            
        Returns:
            New AgentMessage
        """
        if metadata is None:
            metadata = {}
        
        message_content = MessageContent(
            type=message_type,
            content=content,
            metadata=metadata
        )
        
        thread_id = str(uuid.uuid4()) if reply_to is None else None
        
        return AgentMessage(
            sender=self.agent_id,
            receiver=receiver,
            broadcast=broadcast,
            content=message_content,
            thread_id=thread_id,
            reply_to=reply_to
        )
    
    def send_message(self, content: Any, message_type: MessageType, 
                     receiver: str = None, broadcast: bool = False,
                     metadata: Dict[str, Any] = None, reply_to: str = None) -> str:
        """
        Create and send a message.
        
        Args:
            content: Message content
            message_type: Type of message
            receiver: Recipient agent ID
            broadcast: Whether to broadcast the message
            metadata: Additional metadata
            reply_to: ID of message being replied to
            
        Returns:
            ID of the sent message
        """
        message = self.create_message(
            content=content,
            message_type=message_type,
            receiver=receiver,
            broadcast=broadcast,
            metadata=metadata,
            reply_to=reply_to
        )
        
        self.message_bus.send_message(message)
        return message.id
    
    def create_response_message(self, content: Any, original_message: AgentMessage, 
                               metadata: Dict[str, Any] = None) -> AgentMessage:
        """
        Create a response to a message.
        
        Args:
            content: Response content
            original_message: Message being responded to
            metadata: Additional metadata
            
        Returns:
            Response message
        """
        if metadata is None:
            metadata = {}
        
        return self.create_message(
            content=content,
            message_type=MessageType.RESPONSE,
            receiver=original_message.sender,
            broadcast=False,
            metadata=metadata,
            reply_to=original_message.id
        )
    
    def create_error_message(self, error_content: str, receiver: str = None, 
                            reply_to: str = None) -> AgentMessage:
        """
        Create an error message.
        
        Args:
            error_content: Error content
            receiver: Recipient agent ID
            reply_to: ID of message being replied to
            
        Returns:
            Error message
        """
        return self.create_message(
            content=error_content,
            message_type=MessageType.ERROR,
            receiver=receiver,
            broadcast=False,
            metadata={"error": True},
            reply_to=reply_to
        )
    
    def query_llm(self, prompt: str) -> str:
        """
        Query the LLM with a prompt.
        
        Args:
            prompt: Prompt to send to the LLM
            
        Returns:
            LLM response
        """
        performance_monitor.increment_llm_calls()
        try:
            response = self.llm.invoke(prompt)
            return response
        except Exception as e:
            logger.error(f"Error querying LLM: {str(e)}")
            raise
    
    def store_in_memory(self, key: str, value: Any):
        """
        Store a value in the agent's memory.
        
        Args:
            key: Key to store under
            value: Value to store
        """
        self.memory[key] = value
    
    def retrieve_from_memory(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from the agent's memory.
        
        Args:
            key: Key to retrieve
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        return self.memory.get(key, default)
    
    @abstractmethod
    def initialize(self):
        """Initialize the agent. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    def run_cycle(self):
        """Run a single processing cycle. Must be implemented by subclasses."""
        pass


class AgentRegistry:
    """
    Registry for all agents in the system.
    Handles agent creation, retrieval, and lifecycle management.
    """
    
    def __init__(self, message_bus: MessageBus):
        """
        Initialize the agent registry.
        
        Args:
            message_bus: MessageBus for agent communication
        """
        self.agents = {}  # agent_id -> agent instance
        self.agent_types = {}  # agent_type -> agent class
        self.message_bus = message_bus
        logger.info("AgentRegistry initialized")
    
    def register_agent_type(self, agent_type: str, agent_class: Type[BaseAgent]):
        """
        Register an agent type with its implementation class.
        
        Args:
            agent_type: Type name of the agent
            agent_class: Implementation class for the agent type
        """
        self.agent_types[agent_type] = agent_class
        logger.info(f"Registered agent type: {agent_type}")
    
    def create_agent(self, config: AgentConfig) -> BaseAgent:
        """
        Create an agent from configuration.
        
        Args:
            config: Configuration for the agent
            
        Returns:
            Created agent instance
            
        Raises:
            ValueError: If agent type is not registered
        """
        agent_type = config.agent_type
        
        if agent_type not in self.agent_types:
            raise ValueError(f"Agent type not registered: {agent_type}")
        
        agent_class = self.agent_types[agent_type]
        
        # Extract the system reference from message bus
        system_ref = getattr(self.message_bus, 'system', None)
        
        # Basic parameters that all agent constructors accept
        basic_params = {
            "agent_id": config.agent_id,
            "agent_type": config.agent_type,
            "description": config.description,
            "message_bus": self.message_bus,
            "model_name": config.model_name,
            "temperature": config.temperature,
            "system_prompt": config.system_prompt
        }
        
        # Create the agent with only the basic parameters
        agent = agent_class(**basic_params)
        
        # Manually set the system reference after creation
        if system_ref is not None:
            setattr(agent, 'system', system_ref)
            logger.debug(f"Setting system reference on agent {config.agent_id}")
        
        # Store it in the registry
        self.agents[config.agent_id] = agent
        # Initialize the agent
        agent.initialize()
        
        logger.info(f"Created agent: {config.agent_id} ({config.agent_type})")
        return agent
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """
        Get an agent by ID.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            Agent instance or None if not found
        """
        return self.agents.get(agent_id)
    
    def get_all_agents(self) -> Dict[str, BaseAgent]:
        """
        Get all registered agents.
        
        Returns:
            Dictionary of agent ID to agent instance
        """
        return self.agents.copy()
    
    def get_agents_by_type(self, agent_type: str) -> List[BaseAgent]:
        """
        Get all agents of a specific type.
        
        Args:
            agent_type: Type of agents to retrieve
            
        Returns:
            List of agents of the specified type
        """
        return [agent for agent in self.agents.values() if agent.agent_type == agent_type]
    
    def remove_agent(self, agent_id: str) -> bool:
        """
        Remove an agent from the registry.
        
        Args:
            agent_id: ID of the agent to remove
            
        Returns:
            Boolean indicating success
        """
        if agent_id in self.agents:
            # Unsubscribe from message bus
            self.message_bus.unsubscribe(agent_id)
            
            # Remove from registry
            del self.agents[agent_id]
            
            logger.info(f"Removed agent: {agent_id}")
            return True
        
        return False
    
    def load_agents_from_config(self):
        """
        Load all agents from configuration.
        
        Returns:
            Number of agents loaded
        """
        count = 0
        agent_configs = config_manager.get_all_agent_configs()
        
        for agent_id, config_dict in agent_configs.items():
            try:
                config = AgentConfig(**config_dict)
                self.create_agent(config)
                count += 1
            except Exception as e:
                logger.error(f"Error creating agent {agent_id} from config: {str(e)}")
        
        logger.info(f"Loaded {count} agents from configuration")
        return count


class CoordinatorAgent(BaseAgent):
    """
    Coordinator agent that manages workflow across other agents.
    This is a simple implementation that can be extended.
    """
    
    def __init__(self, agent_id: str, agent_type: str, description: str, message_bus: MessageBus,
             model_name: str = DEFAULT_MODEL, temperature: float = DEFAULT_TEMPERATURE,
             system_prompt: str = None, system=None):
        """Initialize the coordinator agent."""
        super().__init__(agent_id, agent_type, description, message_bus, model_name, temperature, system_prompt)
        
        # Subscribe to specific message types
        self.message_bus.subscribe(self.agent_id, [
            MessageType.QUERY.value,
            MessageType.RESULT.value,
            MessageType.STATUS.value
        ])
        
        self.system = system  # Store system reference
    
    def initialize(self):
        """Initialize the coordinator agent."""
        # Set up initial state
        self.store_in_memory("workflows", {})
        self.store_in_memory("active_workflows", set())
        logger.info(f"Coordinator agent {self.agent_id} initialized")
    
    def run_cycle(self):
        """Run a single processing cycle."""
        # Process all pending messages
        self.process_messages()
        
        # Check for completed workflows
        active_workflows = self.retrieve_from_memory("active_workflows", set())
        workflows = self.retrieve_from_memory("workflows", {})
        
        completed = []
        for workflow_id in active_workflows:
            if workflow_id in workflows and workflows[workflow_id].get("status") == "completed":
                completed.append(workflow_id)
        
        # Update active workflows
        for workflow_id in completed:
            active_workflows.remove(workflow_id)
        
        self.store_in_memory("active_workflows", active_workflows)
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query_content = message.content.content
        logger.info(f"Coordinator received query: {query_content}")
        
        # Create a new workflow
        workflow_id = str(uuid.uuid4())
        
        workflows = self.retrieve_from_memory("workflows", {})
        active_workflows = self.retrieve_from_memory("active_workflows", set())
        
        # Store workflow information
        workflows[workflow_id] = {
            "id": workflow_id,
            "query": query_content,
            "created_at": datetime.now().isoformat(),
            "status": "initiated",
            "steps": [],
            "results": {},
            "initiator": message.sender
        }
        
        # Mark as active
        active_workflows.add(workflow_id)
        
        # Update memory
        self.store_in_memory("workflows", workflows)
        self.store_in_memory("active_workflows", active_workflows)
        
        # Process the query with the LLM to determine next steps
        prompt = f"""
        You are a coordinator agent that manages security capability measurement workflows.
        
        You received this query: "{query_content}"
        
        Based on this query, what agents should be involved in processing it?
        What steps should be taken to address the query?
        
        Format your response as a JSON object with these fields:
        - agents: list of agent types needed
        - steps: list of processing steps in order
        - initial_action: first action to take
        """
        
        try:
            performance_monitor.increment_llm_calls()
            response = self.llm.invoke(prompt)
            
            # For demonstration purposes, send a status update to the initiator
            status_message = self.create_message(
                content=f"Query received and workflow {workflow_id} initiated. Processing...",
                message_type=MessageType.STATUS,
                receiver=message.sender,
                metadata={"workflow_id": workflow_id}
            )
            
            self.message_bus.send_message(status_message)
            
            # Return a response
            return self.create_response_message(
                content=f"Query accepted. Workflow ID: {workflow_id}",
                original_message=message,
                metadata={"workflow_id": workflow_id}
            )
            
        except Exception as e:
            logger.error(f"Error processing query: {str(e)}")
            return self.create_error_message(
                error_content=f"Error processing query: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )

    def handle_reports_command(self, command_args, message):
        """
        Handle commands related to reports.
        
        Args:
            command_args: Command arguments
            message: Original message
            
        Returns:
            Response message
        """
        # Parse command arguments
        parts = command_args.split(maxsplit=1)
        
        if not parts:
            return self.create_error_message(
                error_content="Invalid report command format",
                receiver=message.sender,
                reply_to=message.id
            )
        
        action = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Handle list reports action
        if action == "list":
            # Check if report system is available
            system = None
            
            if hasattr(self, 'system'):
                system = self.system
            elif hasattr(self.message_bus, 'system'):
                system = self.message_bus.system
            
            if not system or not hasattr(system, 'report_persistence'):
                return self.create_error_message(
                    error_content="Report persistence system not available",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Parse the report type from args if present
            report_type = args.strip() if args.strip() else None
            
            # Get reports
            if report_type:
                reports = system.report_persistence.get_reports_by_type(report_type)
                response = f"Reports of type '{report_type}':\n\n"
            else:
                reports = system.report_persistence.list_reports()
                response = "All reports:\n\n"
            
            # Format response
            if reports:
                for report in reports:
                    report_id = report.get("id", "Unknown")
                    title = report.get("title", "Untitled")
                    agent_id = report.get("agent_id", "Unknown")
                    generated_at = report.get("generated_at", "Unknown")
                    
                    response += f"- ID: {report_id}\n"
                    response += f"  Title: {title}\n"
                    response += f"  Agent: {agent_id}\n"
                    response += f"  Generated: {generated_at}\n\n"
            else:
                response += "No reports found.\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
        
        # Handle get report action
        elif action == "get":
            report_id = args.strip()
            
            if not report_id:
                return self.create_error_message(
                    error_content="Report ID not provided",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Check if report system is available
            system = None
            
            if hasattr(self, 'system'):
                system = self.system
            elif hasattr(self.message_bus, 'system'):
                system = self.message_bus.system
            
            if not system or not hasattr(system, 'report_persistence'):
                return self.create_error_message(
                    error_content="Report persistence system not available",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Get the report
            report = system.report_persistence.get_report(report_id)
            
            if not report:
                return self.create_error_message(
                    error_content=f"Report with ID '{report_id}' not found",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Return the report content
            return self.create_response_message(
                content=report["content"],
                original_message=message,
                metadata={"report_id": report_id, "report_type": report.get("report_type")}
            )
        
        # Handle types action
        elif action == "types":
            # Check if report system is available
            system = None
            
            if hasattr(self, 'system'):
                system = self.system
            elif hasattr(self.message_bus, 'system'):
                system = self.message_bus.system
            
            if not system or not hasattr(system, 'report_persistence'):
                return self.create_error_message(
                    error_content="Report persistence system not available",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Get report types
            report_types = system.report_persistence.list_report_types()
            
            response = "Available report types:\n\n"
            for report_type in report_types:
                response += f"- {report_type}\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
        
        # Unknown action
        return self.create_error_message(
            error_content=f"Unknown report action: {action}",
            receiver=message.sender,
            reply_to=message.id
        )

    def handle_command(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle command messages.
        
        Args:
            message: Command message
            
        Returns:
            Optional response message
        """
        command = message.content.content
        logger.info(f"Coordinator received command: {command}")
        
        # Parse command
        parts = command.split(maxsplit=1)
        if not parts:
            return self.create_error_message(
                error_content="Empty command received",
                receiver=message.sender,
                reply_to=message.id
            )
        
        command_type = parts[0].lower()
        command_args = parts[1] if len(parts) > 1 else ""
        
        # Process report commands
        if command_type == "report" or command_type == "reports":
            return self.handle_reports_command(command_args, message)
        
        # Process other commands as before
        if command_type == "refresh_inventory":
            # Handle refresh inventory command
            pass
        elif command_type == "collect_metric":
            # Handle collect metric command
            pass
        # ... other command handling ...
        
        # Unknown command
        return self.create_error_message(
            error_content=f"Unknown command: {command_type}",
            receiver=message.sender,
            reply_to=message.id
        )


# Create test functions for this milestone
def test_message_bus():
    """Test the MessageBus functionality."""
    bus = MessageBus()
    
    # Subscribe agents
    bus.subscribe("agent1", [MessageType.NOTIFICATION.value])  # Changed from "test" to NOTIFICATION
    bus.subscribe("agent2")  # This is a wildcard subscription
    
    # Create and send a broadcast message
    message = AgentMessage(
        sender="test",
        broadcast=True,
        content=MessageContent(
            type=MessageType.NOTIFICATION,
            content="Test notification"
        )
    )
    
    success = bus.send_message(message)
    
    # Verify message delivery
    agent1_messages = bus.get_messages("agent1")
    agent2_messages = bus.get_messages("agent2")
    
    return (success and 
            len(agent1_messages) == 1 and 
            len(agent2_messages) == 1 and
            agent1_messages[0].content.content == "Test notification")

def test_agent_creation():
    """Test agent creation and initialization."""
    bus = MessageBus()
    registry = AgentRegistry(bus)
    
    # Register agent type
    registry.register_agent_type("coordinator", CoordinatorAgent)
    
    # Create configuration
    config = AgentConfig(
        agent_id="test_coordinator",
        agent_type="coordinator",
        description="Test coordinator agent"
    )
    
    # Create agent
    agent = registry.create_agent(config)
    
    # Verify agent creation
    return (agent is not None and 
            agent.agent_id == "test_coordinator" and
            agent.agent_type == "coordinator" and
            registry.get_agent("test_coordinator") is agent)


def test_message_passing():
    """Test message passing between agents."""
    bus = MessageBus()
    registry = AgentRegistry(bus)
    
    # Register agent type
    registry.register_agent_type("coordinator", CoordinatorAgent)
    
    # Create coordinator agent
    config = AgentConfig(
        agent_id="test_coordinator",
        agent_type="coordinator",
        description="Test coordinator agent"
    )
    agent = registry.create_agent(config)
    
    # Create a query message
    message = AgentMessage(
        sender="user",
        receiver="test_coordinator",
        content=MessageContent(
            type=MessageType.QUERY,
            content="Test query"
        )
    )
    
    # Send the message
    bus.send_message(message)
    
    # Process messages in coordinator
    agent.process_messages()
    
    # Check for response
    user_messages = bus.get_messages("user")
    
    return len(user_messages) >= 1


# Run tests if this file is executed directly
if __name__ == "__main__":
    print("Testing Core Agent Framework - Base Structure")
    
    tests = [
        ("message_bus", test_message_bus),
        ("agent_creation", test_agent_creation),
        ("message_passing", test_message_passing)
    ]
    
    success_count = 0
    
    for name, test_func in tests:
        print(f"Running test: {name}...", end=" ")
        try:
            result = test_func()
            if result:
                print("✅ PASS")
                success_count += 1
            else:
                print("❌ FAIL")
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
    
    print(f"\nTests complete: {success_count}/{len(tests)} passed.")