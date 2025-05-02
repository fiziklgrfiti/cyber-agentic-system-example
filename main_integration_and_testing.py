#!/usr/bin/env python3
"""
Security Capability Measurement Program - Phase 1 Implementation
Milestone 5: Integration and Testing

This module integrates all components from previous milestones and
implements a demo workflow to validate the foundation.
"""

import os
import sys
import time
import json
import uuid
import logging
import argparse
import datetime
from typing import Dict, List, Any, Tuple, Optional, Union
from pathlib import Path

# Add the specialized agent imports
from inventory_agent import InventoryAgent
from measurement_agent import MeasurementAgent
from analysis_agent import AnalysisAgent

from report_persistence import ReportPersistenceSystem

# Import components from previous milestones
try:
    # Milestone 1: Environment Setup
    from environmental import ( #milestone 1
        MessageType, MessageContent, AgentMessage, AgentConfig,
        LLMManager, PerformanceMonitor, ConfigManager, TestFramework,
        logger
    )
    
    # Milestone 2: Core Agent Framework - Base Structure
    from base_structure import ( #milestone 2
        MessageBus, BaseAgent, AgentRegistry, CoordinatorAgent
    )
    
    # Milestone 3: Core Agent Framework - State and Memory
    from state_and_memory import ( #milestone 3
        InMemoryStore, PersistentStore, JsonStore,
        AgentMemory, ConversationHistory, StateManager
    )
    
    # Milestone 4: Data Management Layer
    from data_management import ( #milestone
        MetricType, MetricStatus, DataSourceType,
        MetricDefinition, MetricValue, DataSourceDefinition,
        DataConnector, CsvConnector, JsonConnector, SqliteConnector,
        DataNormalizer, DataValidator, MetricManager, DataSourceManager
    )
except ImportError:
    # For standalone testing, provide error message
    logger = logging.getLogger('security_measurement')
    logger.error("Could not import components from previous milestones. This file is meant to be used after implementing Milestones 1-4.")
    sys.exit(1)


class SecurityCapabilitySystem:
    """
    Main system class that integrates all components.
    Acts as a facade for the entire security capability measurement system.
    """
    
    def __init__(self, config_path: str = "config/system_config.json"):
        """
        Initialize the system.
        
        Args:
            config_path: Path to the system configuration file
        """
        self.config_path = config_path
        
        # Create necessary directories
        os.makedirs("config", exist_ok=True)
        os.makedirs("data", exist_ok=True)
        
        # Initialize report persistence first
        logger.info("Initializing report persistence system first")
        self.init_report_persistence()
        
        # Initialize core components
        self.llm_manager = LLMManager()
        self.performance_monitor = PerformanceMonitor()
        self.config_manager = ConfigManager(config_path)
        self.test_framework = TestFramework()
        
        # Initialize message bus and agent registry
        self.message_bus = MessageBus()
        # Set system reference on message bus
        self.message_bus.system = self
        logger.debug("Set system reference on message bus")
        
        self.agent_registry = AgentRegistry(self.message_bus)
        
        # Initialize state and memory components
        self.conversation_history = ConversationHistory()
        self.state_manager = StateManager()
        
        # Initialize data management components
        self.metric_manager = MetricManager()
        self.data_source_manager = DataSourceManager()
        self.data_normalizer = DataNormalizer()
        self.data_validator = DataValidator()
        
        # Agent registry
        self.register_agent_types()
        
        # Load agents from configuration
        self.load_agents()
        
        # Make sure all agents have system reference 
        self.update_agent_system_references()
        
        logger.info("SecurityCapabilitySystem initialization complete")

    def update_agent_system_references(self):
        """Explicitly set system reference on all agents"""
        for agent_id, agent in self.agent_registry.get_all_agents().items():
            agent.system = self
            logger.debug(f"Set system reference on agent {agent_id}")

    def init_report_persistence(self):
        """Initialize the report persistence system."""
        from report_persistence import ReportPersistenceSystem
        self.report_persistence = ReportPersistenceSystem()
        logger.info("Report persistence system initialized")

    def register_agent_types(self):
        """Register all agent types with the registry."""
        # Register the coordinator agent
        self.agent_registry.register_agent_type("coordinator", CoordinatorAgent)
        
        # Register specialized agent types with their full implementations
        self.agent_registry.register_agent_type("inventory", InventoryAgent)
        self.agent_registry.register_agent_type("measurement", MeasurementAgent)
        self.agent_registry.register_agent_type("analysis", AnalysisAgent)
        
        logger.info("Agent types registered")
    
    def load_agents(self):
        """Load agent configurations and create agents."""
        # Load agent configurations from the system configuration
        agent_configs = self.config_manager.get_all_agent_configs()
        
        if not agent_configs:
            # Create default coordinator agent if no configuration exists
            self.create_default_coordinator()
        else:
            # Create agents from configuration
            self.agent_registry.load_agents_from_config()
        
        logger.info(f"Loaded {len(self.agent_registry.get_all_agents())} agents")
    
    def create_default_coordinator(self):
        """Create a default coordinator agent and specialized agents if they don't exist."""
        # Create coordinator agent
        coordinator_config = AgentConfig(
            agent_id="coordinator",
            agent_type="coordinator",
            description="Coordinates workflow across all agents",
            system_prompt="You are a coordinator agent that manages workflow across specialized security measurement agents."
        )
        
        # Create inventory agent
        inventory_config = AgentConfig(
            agent_id="inventory_agent",
            agent_type="inventory",
            description="Manages the inventory of security metrics",
            system_prompt="You are an inventory agent responsible for scanning, classifying, and managing security metrics according to NIST SP 800-55 framework."
        )
        
        # Create measurement agent
        measurement_config = AgentConfig(
            agent_id="measurement_agent",
            agent_type="measurement",
            description="Collects and processes security measurements",
            system_prompt="You are a measurement agent responsible for collecting data from various sources and calculating security metrics."
        )
        
        # Create analysis agent
        analysis_config = AgentConfig(
            agent_id="analysis_agent",
            agent_type="analysis",
            description="Analyzes security measurements and provides insights",
            system_prompt="You are an analysis agent responsible for analyzing security metrics, identifying trends, and generating reports."
        )
        
        # Save configurations
        self.config_manager.save_agent_config("coordinator", coordinator_config.model_dump())
        self.config_manager.save_agent_config("inventory_agent", inventory_config.model_dump())
        self.config_manager.save_agent_config("measurement_agent", measurement_config.model_dump())
        self.config_manager.save_agent_config("analysis_agent", analysis_config.model_dump())
        
        # Create agents
        self.agent_registry.create_agent(coordinator_config)
        self.agent_registry.create_agent(inventory_config)
        self.agent_registry.create_agent(measurement_config)
        self.agent_registry.create_agent(analysis_config)
        
        logger.info("Created default agents")
    
    def create_agent(self, agent_config: AgentConfig) -> bool:
        """
        Create a new agent.
        
        Args:
            agent_config: Configuration for the agent
            
        Returns:
            Boolean indicating success
        """
        try:
            # Save configuration
            self.config_manager.save_agent_config(agent_config.agent_id, agent_config.model_dump())
            
            # Create agent
            agent = self.agent_registry.create_agent(agent_config)
            
            return agent is not None
        except Exception as e:
            logger.error(f"Error creating agent: {str(e)}")
            return False
    
    def submit_query(self, query: str, user_id: str = "user") -> str:
        """
        Submit a query to the system.
        
        Args:
            query: Query text
            user_id: ID of the user submitting the query
            
        Returns:
            ID of the conversation thread
        """
        # Find the coordinator agent
        coordinator = self.agent_registry.get_agents_by_type("coordinator")
        
        if not coordinator:
            logger.error("No coordinator agent found")
            return ""
        
        coordinator = coordinator[0]
        
        # Create a query message
        message = AgentMessage(
            sender=user_id,
            receiver=coordinator.agent_id,
            content=MessageContent(
                type=MessageType.QUERY,
                content=query
            )
        )
        
        # Send the message to the coordinator
        self.message_bus.send_message(message)
        
        # Return the thread ID
        return message.id
    
    def process_messages(self, max_cycles: int = 10):
        """
        Process messages in the system.
        
        Args:
            max_cycles: Maximum number of processing cycles
        """
        for _ in range(max_cycles):
            # Process messages for each agent
            for agent_id, agent in self.agent_registry.get_all_agents().items():
                try:
                    # Run agent cycle
                    agent.process_messages()
                    agent.run_cycle()
                except Exception as e:
                    logger.error(f"Error processing messages for agent {agent_id}: {str(e)}")
            
            # Short delay to prevent CPU thrashing
            time.sleep(0.1)
    
    def get_responses(self, user_id: str = "user") -> List[AgentMessage]:
        """
        Get responses for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of messages for the user
        """
        return self.message_bus.get_messages(user_id)

    def list_report_types(self):
        """
        List all available report types.
        
        Returns:
            List of report types
        """
        return self.report_persistence.list_report_types()

    def list_reports(self, report_type=None, limit=None):
        """
        List reports, optionally filtered by type and limited.
        
        Args:
            report_type: Optional type of reports to retrieve
            limit: Maximum number of reports to return
            
        Returns:
            List of report metadata
        """
        if report_type:
            return self.report_persistence.get_reports_by_type(report_type)
        
        return self.report_persistence.list_reports(limit)

    def get_report(self, report_id):
        """
        Get a report by ID.
        
        Args:
            report_id: ID of the report
            
        Returns:
            Report data or None if not found
        """
        return self.report_persistence.get_report(report_id)

    def generate_report(self, report_type: str, period: str = "last month") -> Optional[str]:
        """
        Generate a report directly using the analysis agent.
        
        Args:
            report_type: Type of report ('executive', 'technical', 'compliance', 'trend')
            period: Time period for the report
        
        Returns:
            Report ID or None if generation fails
        """
        # Get the analysis agent
        analysis_agents = self.agent_registry.get_agents_by_type("analysis")
        
        if not analysis_agents:
            logger.error("No analysis agent found for report generation")
            return None
        
        analysis_agent = analysis_agents[0]
        
        # Generate the report
        logger.info(f"Directly generating {report_type} report through analysis agent")
        try:
            report_content = analysis_agent.generate_report(report_type, period)
            
            if not report_content:
                logger.error(f"Failed to generate {report_type} report content")
                return None
            
            # Store report using report persistence system
            report_title = f"{report_type.capitalize()} Security Metrics Report - {period}"
            
            report_id = self.report_persistence.store_report(
                content=report_content,
                title=report_title,
                agent_id=analysis_agent.agent_id,
                report_type=report_type,
                metadata={"period": period, "method": "direct"}
            )
            
            if report_id:
                logger.info(f"Report directly stored with ID: {report_id}")
                return report_id
            else:
                logger.error("Failed to store report directly")
                return None
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}", exc_info=True)
            return None

    def direct_test_report(self):
        """
        Generate a test report directly using the report persistence system.
        
        Returns:
            Report ID or None if generation fails
        """
        if not hasattr(self, 'report_persistence'):
            logger.error("No report persistence system found on system")
            return None
        
        try:
            logger.info("Attempting to directly generate a test report")
            
            report_content = """# Test Report

    This is a test report generated directly by the system to validate the report persistence functionality.

    ## Test Section

    This is a test section.

    ## Conclusion

    If you can see this report, the report persistence system is working correctly.
    """
            
            report_id = self.report_persistence.store_report(
                content=report_content,
                title="Test Report",
                agent_id="system",
                report_type="test",
                metadata={"method": "direct_test"}
            )
            
            if report_id:
                logger.info(f"Test report successfully stored with ID: {report_id}")
                return report_id
            else:
                logger.error("Failed to store test report directly")
                return None
        except Exception as e:
            logger.error(f"Error generating test report: {str(e)}", exc_info=True)
            return None

    def generate_comprehensive_report(self, report_type: str, period: str = "last month") -> Optional[str]:
        """
        Generate a comprehensive report directly, using metrics data.
        
        Args:
            report_type: Type of report ('executive', 'technical', 'compliance', 'trend')
            period: Time period for the report
        
        Returns:
            Report ID or None if generation fails
        """
        logger.info(f"Generating comprehensive {report_type} report directly")
        
        # Get metrics and values
        metrics = self.metric_manager.list_metrics()
        if not metrics:
            logger.warning("No metrics available for report generation")
            return None
        
        # Prepare metrics data with analyses
        metrics_analysis = {}
        for metric in metrics:
            # Get metric values
            values = self.metric_manager.get_metric_values(metric.id)
            if not values:
                continue
                
            # Calculate basic statistics
            values_list = [v.value for v in values]
            
            # Basic statistics
            stats = {
                "count": len(values_list),
                "mean": sum(values_list) / len(values_list) if values_list else 0,
                "min": min(values_list) if values_list else 0,
                "max": max(values_list) if values_list else 0,
            }
            
            # Calculate trend
            if len(values_list) >= 2:
                first_value = values_list[0]
                last_value = values_list[-1]
                
                if first_value != 0:
                    percentage_change = ((last_value - first_value) / abs(first_value)) * 100
                else:
                    percentage_change = 100 if last_value > 0 else 0
                    
                if abs(percentage_change) < 5:
                    direction = "stable"
                    description = "The metric has remained relatively stable"
                elif percentage_change > 0:
                    direction = "increasing"
                    description = "The metric has increased"
                else:
                    direction = "decreasing"
                    description = "The metric has decreased"
                    
                trend = {
                    "direction": direction,
                    "description": description,
                    "percentage_change": percentage_change,
                    "first_value": first_value,
                    "last_value": last_value
                }
            else:
                trend = {
                    "direction": "stable",
                    "description": "Insufficient data for trend analysis",
                    "percentage_change": 0
                }
            
            # Store metrics analysis
            metrics_analysis[metric.id] = {
                "metric": metric,
                "current_value": values[-1].value if values else None,
                "statistics": stats,
                "trend": trend,
                "values": values
            }
        
        # Generate report content based on type
        report_title = f"{report_type.capitalize()} Security Metrics Report - {period}"
        report_content = ""
        
        if report_type == "executive":
            report_content = self._generate_executive_report(metrics_analysis, period)
        elif report_type == "technical":
            report_content = self._generate_technical_report(metrics_analysis, period)
        elif report_type == "compliance":
            report_content = self._generate_compliance_report(metrics_analysis, period)
        elif report_type == "trend":
            report_content = self._generate_trend_report(metrics_analysis, period)
        else:
            # Generate a generic report
            report_content = self._generate_generic_report(report_type, metrics_analysis, period)
        
        # Store the report
        report_id = self.report_persistence.store_report(
            content=report_content,
            title=report_title,
            agent_id="system",
            report_type=report_type,
            metadata={"period": period, "method": "comprehensive_system"}
        )
        
        if report_id:
            logger.info(f"Comprehensive report stored with ID: {report_id}")
            return report_id
        else:
            logger.error("Failed to store comprehensive report")
            return None

    def _generate_executive_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate an executive summary report."""
        report = f"# Executive Security Metrics Report - {period}\n\n"
        
        # Generate overview section
        report += "## Overview\n\n"
        
        total_metrics = len(metrics_analysis)
        improving_count = sum(1 for analysis in metrics_analysis.values() 
                            if analysis["trend"]["direction"] == "increasing")
        declining_count = sum(1 for analysis in metrics_analysis.values() 
                            if analysis["trend"]["direction"] == "decreasing")
        stable_count = sum(1 for analysis in metrics_analysis.values() 
                        if analysis["trend"]["direction"] == "stable")
        
        report += f"This report provides an executive summary of {total_metrics} security metrics for the period: {period}.\n\n"
        report += f"Overall, {improving_count} metrics are improving, {stable_count} are stable, and {declining_count} are declining.\n\n"
        
        # Group metrics by type
        metrics_by_type = {}
        for metric_id, analysis in metrics_analysis.items():
            metric_type = analysis["metric"].type
            if metric_type not in metrics_by_type:
                metrics_by_type[metric_type] = []
            metrics_by_type[metric_type].append((metric_id, analysis))
        
        # Add metrics summary
        report += "## Key Metrics Summary\n\n"
        
        for metric_type, metrics in metrics_by_type.items():
            report += f"### {metric_type.value.capitalize()} Metrics\n\n"
            
            for metric_id, analysis in metrics:
                metric = analysis["metric"]
                current_value = analysis["current_value"]
                trend = analysis["trend"]
                
                report += f"#### {metric.name}\n\n"
                report += f"Current Value: {current_value} {metric.unit}\n\n"
                report += f"Trend: {trend['direction'].capitalize()} ({trend['percentage_change']:.1f}%)\n\n"
        
        # Add recommendations
        report += "## Recommendations\n\n"
        
        # Find metrics that need attention
        attention_metrics = []
        for metric_id, analysis in metrics_analysis.items():
            metric = analysis["metric"]
            trend = analysis["trend"]
            
            if trend["direction"] == "decreasing" and metric.type != MetricType.EFFICIENCY:
                attention_metrics.append((metric, "declining trend"))
        
        if attention_metrics:
            for metric, reason in attention_metrics[:3]:  # Show top 3
                report += f"1. **{metric.name}**: Investigate the {reason} and develop an improvement plan.\n\n"
        else:
            report += "1. Continue monitoring all metrics and maintain current security practices.\n\n"
            report += "2. Consider developing additional metrics for areas not currently measured.\n\n"
        
        return report

    def _generate_technical_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a technical report."""
        report = f"# Technical Security Metrics Report - {period}\n\n"
        
        # Add metrics details
        report += "## Metrics Details\n\n"
        
        for metric_id, analysis in metrics_analysis.items():
            metric = analysis["metric"]
            stats = analysis["statistics"]
            trend = analysis["trend"]
            
            report += f"### {metric.name} ({metric.id})\n\n"
            report += f"Type: {metric.type.value.capitalize()}\n\n"
            report += f"Description: {metric.description}\n\n"
            report += f"Formula: {metric.formula}\n\n"
            report += f"Unit: {metric.unit}\n\n"
            
            # Add statistics section
            report += "Statistics:\n"
            for key, value in stats.items():
                if key != "outliers":
                    report += f"- {key.capitalize()}: {value}\n"
            report += "\n"
            
            # Add trend section
            report += "Trend:\n"
            report += f"- Direction: {trend.get('direction', 'Unknown')}\n"
            report += f"- Change: {trend.get('percentage_change', 0):.2f}%\n\n"
        
        # Add analysis methodology
        report += "## Analysis Methodology\n\n"
        report += """
        The following analysis methods were used:
        
        - **Descriptive Statistics**: Mean, minimum, maximum, and count to characterize the distribution of metric values.
        
        - **Trend Analysis**: Calculation of percentage change over time and characterization of trend direction.
        """
        
        return report

    def _generate_compliance_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a compliance report."""
        report = f"# Compliance Security Metrics Report - {period}\n\n"
        
        # Get implementation metrics
        implementation_metrics = {}
        for metric_id, analysis in metrics_analysis.items():
            metric = analysis["metric"]
            if metric.type == MetricType.IMPLEMENTATION:
                implementation_metrics[metric_id] = analysis
        
        # Generate compliance overview
        report += "## Compliance Overview\n\n"
        
        total_controls = len(implementation_metrics)
        if total_controls > 0:
            report += f"This report assesses compliance across {total_controls} security controls.\n\n"
            
            # Determine compliance status
            controls_meeting_target = 0
            controls_near_target = 0
            controls_below_target = 0
            
            for metric_id, analysis in implementation_metrics.items():
                metric = analysis["metric"]
                current_value = analysis["current_value"]
                
                if metric.target is not None and current_value is not None:
                    try:
                        target = float(metric.target)
                        value = float(current_value)
                        
                        if value >= target:
                            controls_meeting_target += 1
                        elif value >= target * 0.9:
                            controls_near_target += 1
                        else:
                            controls_below_target += 1
                    except (ValueError, TypeError):
                        controls_below_target += 1
                else:
                    controls_below_target += 1
            
            compliance_percentage = (controls_meeting_target / total_controls * 100) if total_controls > 0 else 0
            
            report += f"Overall compliance: {compliance_percentage:.1f}%\n\n"
            report += f"- Controls meeting targets: {controls_meeting_target} ({(controls_meeting_target / total_controls * 100):.1f}%)\n"
            report += f"- Controls approaching targets: {controls_near_target} ({(controls_near_target / total_controls * 100):.1f}%)\n"
            report += f"- Controls below targets: {controls_below_target} ({(controls_below_target / total_controls * 100):.1f}%)\n\n"
        else:
            report += "No implementation metrics available for compliance assessment.\n\n"
        
        return report

    def _generate_trend_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a trend report."""
        report = f"# Trend Security Metrics Report - {period}\n\n"
        
        # Generate trend summary
        report += "## Trend Summary\n\n"
        
        # Count trends by direction
        increasing = 0
        decreasing = 0
        stable = 0
        
        for metric_id, analysis in metrics_analysis.items():
            trend = analysis["trend"]
            
            if trend["direction"] == "increasing":
                increasing += 1
            elif trend["direction"] == "decreasing":
                decreasing += 1
            elif trend["direction"] == "stable":
                stable += 1
        
        report += f"Overall trend summary:\n"
        report += f"- {increasing} metrics show an increasing trend\n"
        report += f"- {stable} metrics show a stable trend\n"
        report += f"- {decreasing} metrics show a decreasing trend\n\n"
        
        # Generate individual metrics trends
        report += "## Individual Metric Trends\n\n"
        
        # Group metrics by type
        metrics_by_type = {}
        for metric_id, analysis in metrics_analysis.items():
            metric_type = analysis["metric"].type
            if metric_type not in metrics_by_type:
                metrics_by_type[metric_type] = []
            metrics_by_type[metric_type].append((metric_id, analysis))
        
        for metric_type, metrics in metrics_by_type.items():
            report += f"### {metric_type.value.capitalize()} Metrics\n\n"
            
            for metric_id, analysis in metrics:
                metric = analysis["metric"]
                trend = analysis["trend"]
                
                report += f"#### {metric.name}\n\n"
                report += f"- Direction: {trend.get('direction', 'Unknown').capitalize()}\n"
                report += f"- Change: {trend.get('percentage_change', 0):.1f}%\n"
                report += f"- Description: {trend.get('description', 'No description available')}\n\n"
        
        return report

    def _generate_generic_report(self, report_type: str, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a generic report if the specific type is not recognized."""
        report = f"# {report_type.capitalize()} Security Metrics Report - {period}\n\n"
        
        report += "## Overview\n\n"
        report += f"This is a generic {report_type} report generated on {datetime.datetime.now().isoformat()}.\n\n"
        
        report += "## Metrics Summary\n\n"
        
        for metric_id, analysis in metrics_analysis.items():
            metric = analysis["metric"]
            current_value = analysis["current_value"]
            
            report += f"### {metric.name}\n\n"
            report += f"- Type: {metric.type.value}\n"
            report += f"- Current Value: {current_value} {metric.unit}\n"
            report += f"- Description: {metric.description}\n\n"
        
        return report
        
    
    def shutdown(self):
        """Shutdown the system."""
        # Close all data source connections
        self.data_source_manager.close_all_connections()
        
        logger.info("System shutdown complete")


class InventoryAgent(BaseAgent):
    """
    Agent responsible for managing the inventory of security metrics.
    This is a placeholder implementation that will be expanded in future phases.
    """
    
    def initialize(self):
        """Initialize the inventory agent."""
        self.store_in_memory("metrics", {})
        logger.info(f"InventoryAgent {self.agent_id} initialized")
    
    def run_cycle(self):
        """Run a processing cycle."""
        pass
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages by determining which specialized agent should process it.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"Coordinator received query: {query}")
        
        # Create a new workflow
        workflow_id = str(uuid.uuid4())
        
        # Store workflow information
        workflows = self.retrieve_from_memory("workflows", {})
        active_workflows = self.retrieve_from_memory("active_workflows", set())
        
        # Store workflow information
        workflows[workflow_id] = {
            "id": workflow_id,
            "query": query,
            "created_at": datetime.datetime.now().isoformat(),
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
        
        # Analyze the query to determine which agent should handle it
        prompt = f"""
        You are a coordinator agent that routes security metric queries to specialized agents.
        
        You received this query: "{query}"
        
        Based on this query, determine which agent should handle it:
        
        1. inventory_agent - For queries about the inventory of security metrics, classification, or gap analysis
        2. measurement_agent - For queries about collecting metric values, data sources, or measurement schedules
        3. analysis_agent - For queries about analyzing metrics, generating reports, trends, or recommendations
        
        Reply with ONLY ONE agent name from the options above.
        """
        
        try:
            # Ask LLM which agent should handle this query
            response = self.query_llm(prompt)
            
            # Extract agent name from response
            if "inventory" in response.lower():
                target_agent = "inventory_agent"
            elif "measurement" in response.lower():
                target_agent = "measurement_agent"
            elif "analysis" in response.lower():
                target_agent = "analysis_agent"
            else:
                # Default to inventory agent if unclear
                target_agent = "inventory_agent"
            
            logger.info(f"Routing query to {target_agent}")
            
            # Forward the query to the appropriate agent
            forward_message = self.create_message(
                content=query,
                message_type=MessageType.QUERY,
                receiver=target_agent,
                metadata={"workflow_id": workflow_id, "original_sender": message.sender}
            )
            
            self.message_bus.send_message(forward_message)
            
            # Update workflow status
            workflows[workflow_id]["status"] = "routed"
            workflows[workflow_id]["steps"].append({
                "action": "routed",
                "target": target_agent,
                "timestamp": datetime.datetime.now().isoformat()
            })
            
            self.store_in_memory("workflows", workflows)
            
            # Send acknowledgment to the user
            return self.create_response_message(
                content=f"I've routed your query about security metrics to our {target_agent.replace('_', ' ')}. You'll receive a response shortly.",
                original_message=message,
                metadata={"workflow_id": workflow_id}
            )
            
        except Exception as e:
            logger.error(f"Error routing query: {str(e)}")
            
            # Update workflow status
            workflows[workflow_id]["status"] = "error"
            workflows[workflow_id]["error"] = str(e)
            self.store_in_memory("workflows", workflows)
            
            return self.create_error_message(
                error_content=f"Error processing query: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def handle_response(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle response messages from specialized agents.
        
        Args:
            message: Response message
            
        Returns:
            Optional response message to forward
        """
        response_content = message.content.content
        logger.info(f"Coordinator received response from {message.sender}")
        
        # Check if this is a response to a workflow
        workflow_id = message.content.metadata.get("workflow_id")
        original_sender = message.content.metadata.get("original_sender")
        
        if not workflow_id or not original_sender:
            logger.warning(f"Response from {message.sender} missing workflow_id or original_sender")
            return None
        
        # Get workflow
        workflows = self.retrieve_from_memory("workflows", {})
        workflow = workflows.get(workflow_id)
        
        if not workflow:
            logger.warning(f"Workflow {workflow_id} not found")
            return None
        
        # Update workflow status
        workflow["status"] = "completed"
        workflow["steps"].append({
            "action": "response_received",
            "from": message.sender,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
        # Store response in workflow
        workflow["results"][message.sender] = response_content
        
        # Update workflow
        workflows[workflow_id] = workflow
        self.store_in_memory("workflows", workflows)
        
        # Forward the response to the original sender
        forward_response = self.create_message(
            content=response_content,
            message_type=MessageType.RESPONSE,
            receiver=original_sender,
            metadata={"workflow_id": workflow_id, "source_agent": message.sender}
        )
        
        self.message_bus.send_message(forward_response)
        
        # Mark workflow as inactive if complete
        active_workflows = self.retrieve_from_memory("active_workflows", set())
        if workflow_id in active_workflows:
            active_workflows.remove(workflow_id)
            self.store_in_memory("active_workflows", active_workflows)
        
        return None


class MeasurementAgent(BaseAgent):
    """
    Agent responsible for collecting and processing security measurements.
    This is a placeholder implementation that will be expanded in future phases.
    """
    
    def initialize(self):
        """Initialize the measurement agent."""
        self.store_in_memory("measurements", {})
        logger.info(f"MeasurementAgent {self.agent_id} initialized")
    
    def run_cycle(self):
        """Run a processing cycle."""
        pass
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"MeasurementAgent received query: {query}")
        
        # Simple response for now
        return self.create_response_message(
            content=f"MeasurementAgent acknowledges query: {query}",
            original_message=message
        )


class AnalysisAgent(BaseAgent):
    """
    Agent responsible for analyzing security measurements.
    This is a placeholder implementation that will be expanded in future phases.
    """
    
    def initialize(self):
        """Initialize the analysis agent."""
        self.store_in_memory("analyses", {})
        logger.info(f"AnalysisAgent {self.agent_id} initialized")
    
    def run_cycle(self):
        """Run a processing cycle."""
        pass
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"AnalysisAgent received query: {query}")
        
        # Simple response for now
        return self.create_response_message(
            content=f"AnalysisAgent acknowledges query: {query}",
            original_message=message
        )


# Demo workflow functions

def create_sample_metrics(metric_manager: MetricManager):
    """
    Create sample metrics for demonstration.
    
    Args:
        metric_manager: MetricManager instance
    """
    # Create sample implementation metrics
    imp_metrics = [
        MetricDefinition(
            id="sec_training_completion",
            name="Security Training Completion Rate",
            description="Percentage of employees who have completed required security training",
            type=MetricType.IMPLEMENTATION,
            formula="(completed_training / total_employees) * 100",
            unit="percentage"
        ),
        MetricDefinition(
            id="vuln_patch_coverage",
            name="Vulnerability Patch Coverage",
            description="Percentage of systems patched for known vulnerabilities",
            type=MetricType.IMPLEMENTATION,
            formula="(patched_systems / total_systems) * 100",
            unit="percentage"
        )
    ]
    
    # Create sample effectiveness metrics
    eff_metrics = [
        MetricDefinition(
            id="sec_incident_rate",
            name="Security Incident Rate",
            description="Number of security incidents per month",
            type=MetricType.EFFECTIVENESS,
            formula="count(incidents) / month",
            unit="incidents/month"
        ),
        MetricDefinition(
            id="mean_time_to_detect",
            name="Mean Time to Detect",
            description="Average time to detect security incidents",
            type=MetricType.EFFECTIVENESS,
            formula="average(detection_time)",
            unit="hours"
        )
    ]
    
    # Create all metrics
    for metric in imp_metrics + eff_metrics:
        if not metric_manager.get_metric(metric.id):
            metric_manager.create_metric(metric)
            logger.info(f"Created sample metric: {metric.id}")


def create_sample_data_sources(data_source_manager: DataSourceManager):
    """
    Create sample data sources for demonstration.
    
    Args:
        data_source_manager: DataSourceManager instance
    """
    # Create a test CSV file for training data
    training_file = "data/sample_training_data.csv"
    os.makedirs(os.path.dirname(training_file), exist_ok=True)
    
    with open(training_file, 'w') as f:
        f.write("employee_id,name,department,completed_date\n")
        f.write("E001,John Smith,IT,2023-01-15\n")
        f.write("E002,Jane Doe,HR,2023-01-20\n")
        f.write("E003,Robert Johnson,Finance,2023-01-10\n")
        f.write("E004,Sarah Williams,Marketing,\n")
        f.write("E005,Michael Brown,IT,2023-01-25\n")
    
    # Create a test JSON file for vulnerability data
    vuln_file = "data/sample_vulnerability_data.json"
    
    vuln_data = {
        "scan_date": "2023-02-01",
        "systems": [
            {"id": "S001", "name": "Web Server", "vulnerabilities": 5, "patched": 4},
            {"id": "S002", "name": "Database Server", "vulnerabilities": 3, "patched": 3},
            {"id": "S003", "name": "File Server", "vulnerabilities": 2, "patched": 1},
            {"id": "S004", "name": "Mail Server", "vulnerabilities": 4, "patched": 2}
        ]
    }
    
    with open(vuln_file, 'w') as f:
        json.dump(vuln_data, f, indent=2)
    
    # Create data sources
    sources = [
        DataSourceDefinition(
            id="training_data",
            name="Security Training Data",
            type=DataSourceType.CSV,
            location=training_file,
            description="Employee security training completion data",
            configuration={"has_header": True}
        ),
        DataSourceDefinition(
            id="vulnerability_data",
            name="Vulnerability Scan Data",
            type=DataSourceType.JSON,
            location=vuln_file,
            description="System vulnerability and patching data",
            configuration={"root_path": "systems"}
        )
    ]
    
    # Create all data sources
    for source in sources:
        if not data_source_manager.get_data_source(source.id):
            data_source_manager.create_data_source(source)
            logger.info(f"Created sample data source: {source.id}")


def calculate_sample_metrics(system: SecurityCapabilitySystem):
    """
    Calculate sample metrics from data sources.
    
    Args:
        system: SecurityCapabilitySystem instance
    """
    # Get components
    metric_manager = system.metric_manager
    data_source_manager = system.data_source_manager
    
    # Calculate security training completion rate
    try:
        # Get training data
        training_data = data_source_manager.fetch_data("training_data")
        
        if training_data:
            total_employees = len(training_data)
            completed_training = sum(1 for record in training_data if record.get("completed_date"))
            
            completion_rate = (completed_training / total_employees) * 100 if total_employees > 0 else 0
            
            # Create metric value
            metric_value = MetricValue(
                metric_id="sec_training_completion",
                value=completion_rate,
                source="training_data",
                collection_method="automated",
                notes=f"Based on {total_employees} employees"
            )
            
            # Add metric value
            metric_manager.add_metric_value(metric_value)
            logger.info(f"Calculated security training completion rate: {completion_rate:.1f}%")
    
    except Exception as e:
        logger.error(f"Error calculating security training completion rate: {str(e)}")
    
    # Calculate vulnerability patch coverage
    try:
        # Get vulnerability data
        vuln_data = data_source_manager.fetch_data("vulnerability_data")
        
        if vuln_data:
            total_vulns = sum(record.get("vulnerabilities", 0) for record in vuln_data)
            patched_vulns = sum(record.get("patched", 0) for record in vuln_data)
            
            patch_coverage = (patched_vulns / total_vulns) * 100 if total_vulns > 0 else 0
            
            # Create metric value
            metric_value = MetricValue(
                metric_id="vuln_patch_coverage",
                value=patch_coverage,
                source="vulnerability_data",
                collection_method="automated",
                notes=f"Based on {len(vuln_data)} systems with {total_vulns} vulnerabilities"
            )
            
            # Add metric value
            metric_manager.add_metric_value(metric_value)
            logger.info(f"Calculated vulnerability patch coverage: {patch_coverage:.1f}%")
    
    except Exception as e:
        logger.error(f"Error calculating vulnerability patch coverage: {str(e)}")


def run_demo_workflow():
    """Run a demo workflow to validate the system with specialized agents."""
    # Initialize the system
    system = SecurityCapabilitySystem()
    
    # Create sample metrics and data sources
    create_sample_metrics(system.metric_manager)
    create_sample_data_sources(system.data_source_manager)
    
    # Calculate sample metrics
    calculate_sample_metrics(system)
    
    # List all metrics
    metrics = system.metric_manager.list_metrics()
    print("\nAvailable Metrics:")
    for metric in metrics:
        print(f"- {metric.id}: {metric.name} ({metric.type.value})")
    
    # Get values for a specific metric
    print("\nMetric Values:")
    for metric in metrics:
        values = system.metric_manager.get_metric_values(metric.id)
        for value in values:
            print(f"- {metric.name}: {value.value:.1f} {metric.unit} ({value.timestamp})")
    
    # Test all specialized agents with appropriate queries
    print("\nTesting specialized agents...")
    
    # Test inventory agent
    print("\n1. Testing Inventory Agent:")
    inventory_query = "List all security metrics in our inventory"
    inventory_thread_id = system.submit_query(inventory_query)
    
    # Process messages
    system.process_messages(max_cycles=5)
    
    # Get responses
    inventory_responses = system.get_responses()
    print("Inventory Agent Response:")
    for response in inventory_responses:
        print(f"- {response.content.content}")
    
    # Test measurement agent
    print("\n2. Testing Measurement Agent:")
    measurement_query = "What is the current value of our security training completion rate metric?"
    measurement_thread_id = system.submit_query(measurement_query)
    
    # Process messages
    system.process_messages(max_cycles=5)
    
    # Get responses
    measurement_responses = system.get_responses()
    print("Measurement Agent Response:")
    for response in measurement_responses:
        print(f"- {response.content.content}")
    
    # Test analysis agent
    print("\n3. Testing Analysis Agent:")
    analysis_query = "Generate an executive report on our security metrics"
    analysis_thread_id = system.submit_query(analysis_query)
    
    # Process messages
    system.process_messages(max_cycles=5)
    
    # Get responses
    analysis_responses = system.get_responses()
    print("Analysis Agent Response:")
    for response in analysis_responses:
        print(f"- {response.content.content}")
    
    # Shutdown the system
    system.shutdown()
    print("\nDemo workflow completed successfully!")

def run_demo_workflow_with_reports():
    """Run a demo workflow with report persistence."""
    # Initialize the system
    system = SecurityCapabilitySystem()
    
    # Create sample metrics and data sources
    create_sample_metrics(system.metric_manager)
    create_sample_data_sources(system.data_source_manager)
    
    # Calculate sample metrics
    calculate_sample_metrics(system)
    
    # List all metrics
    metrics = system.metric_manager.list_metrics()
    print("\nAvailable Metrics:")
    for metric in metrics:
        print(f"- {metric.id}: {metric.name} ({metric.type.value})")
    
    # Generate reports directly with the comprehensive generator
    print("\nGenerating comprehensive reports directly...")
    for report_type in ["executive", "technical", "compliance", "trend"]:
        report_id = system.generate_comprehensive_report(report_type, f"{report_type} report period")
        if report_id:
            print(f"- Successfully generated {report_type} report with ID: {report_id}")
        else:
            print(f"- Failed to generate {report_type} report")
    
    # List all reports
    print("\nListing all reports:")
    reports = system.list_reports()
    for report in reports:
        print(f"- {report['id']}: {report['title']} ({report['report_type']})")
    
    # Show an example of retrieving a specific report
    if reports:
        first_report_id = reports[0]['id']
        print(f"\nRetrieving report {first_report_id}:")
        report = system.get_report(first_report_id)
        
        if report:
            print(f"Title: {report['title']}")
            print(f"Type: {report['report_type']}")
            print(f"Agent: {report['agent_id']}")
            print(f"Generated: {report['generated_at']}")
            print("\nContent preview:")
            content_preview = report['content'][:200] + "..." if len(report['content']) > 200 else report['content']
            print(content_preview)
    
    # Shutdown the system
    system.shutdown()
    print("\nDemo workflow with reports completed successfully!")

def add_report_cli_commands(parser):
    """Add report-related commands to the CLI parser."""
    # Add report subparser
    report_parser = parser.add_subparsers(dest="report_command", help="Report commands")
    
    # Add list command
    list_parser = report_parser.add_parser("list", help="List reports")
    list_parser.add_argument("--type", "-t", help="Filter by report type")
    list_parser.add_argument("--limit", "-l", type=int, help="Limit number of reports")
    
    # Add get command
    get_parser = report_parser.add_parser("get", help="Get a report")
    get_parser.add_argument("report_id", help="ID of the report to retrieve")
    
    # Add types command
    report_parser.add_parser("types", help="List available report types")
    
    return parser


def handle_report_cli_command(args, system):
    """Handle report-related CLI commands."""
    if args.report_command == "list":
        # List reports
        reports = system.list_reports(report_type=args.type, limit=args.limit)
        
        if not reports:
            print("No reports found.")
            return
        
        print(f"Found {len(reports)} reports:")
        for report in reports:
            print(f"- {report['id']}: {report['title']} ({report['report_type']})")
    
    elif args.report_command == "get":
        # Get a report
        report = system.get_report(args.report_id)
        
        if not report:
            print(f"Report with ID '{args.report_id}' not found.")
            return
        
        print(f"Report: {report['title']}")
        print(f"Type: {report['report_type']}")
        print(f"Agent: {report['agent_id']}")
        print(f"Generated: {report['generated_at']}")
        print("\nContent:")
        print(report['content'])
    
    elif args.report_command == "types":
        # List report types
        report_types = system.list_report_types()
        
        print("Available report types:")
        for report_type in report_types:
            print(f"- {report_type}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Security Capability Measurement System - Phase 1")
    parser.add_argument("--demo", action="store_true", help="Run demo workflow")
    parser.add_argument("--test", action="store_true", help="Run integration tests")
    
    # Add report commands
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Add report subparser
    report_parser = subparsers.add_parser("report", help="Report commands")
    report_subparsers = report_parser.add_subparsers(dest="report_command", help="Report commands")
    
    # Add list command
    list_parser = report_subparsers.add_parser("list", help="List reports")
    list_parser.add_argument("--type", "-t", help="Filter by report type")
    list_parser.add_argument("--limit", "-l", type=int, help="Limit number of reports")
    
    # Add get command
    get_parser = report_subparsers.add_parser("get", help="Get a report")
    get_parser.add_argument("report_id", help="ID of the report to retrieve")
    get_parser.add_argument("--output", "-o", help="Output file path")
    
    # Add types command
    report_subparsers.add_parser("types", help="List available report types")
    
    args = parser.parse_args()
    
    if args.command == "report":
        # Initialize the system
        system = SecurityCapabilitySystem()
        
        if args.report_command == "list":
            # List reports
            reports = system.list_reports(report_type=args.type, limit=args.limit)
            
            if not reports:
                print("No reports found.")
                return
            
            print(f"Found {len(reports)} reports:")
            for report in reports:
                print(f"- {report['id']}: {report['title']} ({report['report_type']})")
        
        elif args.report_command == "get":
            # Get a report
            report = system.get_report(args.report_id)
            
            if not report:
                print(f"Report with ID '{args.report_id}' not found.")
                return
            
            print(f"Report: {report['title']}")
            print(f"Type: {report['report_type']}")
            print(f"Agent: {report['agent_id']}")
            print(f"Generated: {report['generated_at']}")
            
            if args.output:
                # Write report to file
                with open(args.output, 'w') as f:
                    f.write(report['content'])
                print(f"Report written to {args.output}")
            else:
                print("\nContent:")
                print(report['content'])
        
        elif args.report_command == "types":
            # List report types
            report_types = system.list_report_types()
            
            print("Available report types:")
            for report_type in report_types:
                print(f"- {report_type}")
    
    elif args.demo:
        run_demo_workflow_with_reports()
    elif args.test:
        # Run integration tests
        print("Running integration tests...")
        # TODO: Implement integration tests
        print("Integration tests completed.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()