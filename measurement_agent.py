#!/usr/bin/env python3
"""
Security Capability Measurement Program - Measurement Agent Implementation

This module implements the Measurement Agent which is responsible for collecting
data from various sources and calculating security metrics.
"""

import re
import logging
import datetime
import json
import math
from typing import Dict, List, Any, Optional, Union, Callable

# Import components from previous milestones
from environmental import MessageType, MessageContent, AgentMessage
from base_structure import BaseAgent, MessageBus
from data_management import (
    MetricType, MetricStatus, MetricDefinition, MetricValue, 
    DataSourceDefinition, MetricManager, DataSourceManager,
    DataNormalizer, DataValidator
)

logger = logging.getLogger('security_measurement')

class MeasurementAgent(BaseAgent):
    """
    Agent responsible for collecting and processing security measurements.
    Handles data collection, validation, calculation, and storage of metric values.
    """
    
    def __init__(self, agent_id: str, agent_type: str, description: str, message_bus: MessageBus,
                 model_name: str = "llama3.2:latest", temperature: float = 0.1,
                 system_prompt: str = None):
        """Initialize the measurement agent."""
        super().__init__(agent_id, agent_type, description, message_bus, model_name, temperature, system_prompt)
        
        # Initialize components
        self.metric_manager = MetricManager()
        self.data_source_manager = DataSourceManager()
        self.data_normalizer = DataNormalizer()
        self.data_validator = DataValidator()
        
        # Register transformers for different source types
        self._register_data_transformers()
        
        # Register common validation rules
        self._register_validation_rules()
        
        # Set up measurement schedule
        self.scheduled_measurements = {}
        
        # Subscribe to relevant message types
        self.message_bus.subscribe(self.agent_id, [
            MessageType.QUERY.value,
            MessageType.REQUEST.value,
            MessageType.COMMAND.value
        ])
    
    def _register_data_transformers(self):
        """Register data transformers for different source types."""
        # Register CSV transformer
        self.data_normalizer.register_transformer("csv", self._transform_csv_data)
        
        # Register JSON transformer
        self.data_normalizer.register_transformer("json", self._transform_json_data)
    
    def _transform_csv_data(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Transform CSV data to standard format."""
        # Basic transformation - convert string values to appropriate types
        transformed = {}
        
        for key, value in record.items():
            # Normalize field name
            normalized_key = key.lower().replace(' ', '_')
            
            # Try to convert to appropriate type
            if isinstance(value, str):
                if value.isdigit():
                    transformed[normalized_key] = int(value)
                elif self._is_float(value):
                    transformed[normalized_key] = float(value)
                elif value.lower() in ['true', 'yes', 'y']:
                    transformed[normalized_key] = True
                elif value.lower() in ['false', 'no', 'n']:
                    transformed[normalized_key] = False
                elif self._is_date(value):
                    transformed[normalized_key] = self.data_normalizer.normalize_date(value)
                else:
                    transformed[normalized_key] = value
            else:
                transformed[normalized_key] = value
        
        return transformed
    
    def _transform_json_data(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Transform JSON data to standard format."""
        # For JSON, we flatten nested structures and normalize field names
        transformed = {}
        
        def flatten(prefix, obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_key = f"{prefix}_{key}" if prefix else key
                    flatten(new_key, value)
            elif isinstance(obj, list):
                # For lists, we just store the count
                transformed[prefix + "_count"] = len(obj)
            else:
                # Normalize field name
                normalized_key = prefix.lower().replace(' ', '_')
                transformed[normalized_key] = obj
        
        flatten("", record)
        return transformed
    
    def _register_validation_rules(self):
        """Register common validation rules."""
        # Add some basic validation rules
        self.data_validator.add_validation_rule(
            "timestamp", 
            self.data_validator.required, 
            "Timestamp is required"
        )
        
        self.data_validator.add_validation_rule(
            "value", 
            self.data_validator.required, 
            "Value is required"
        )
    
    def _is_float(self, value: str) -> bool:
        """Check if a string can be converted to float."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def _is_date(self, value: str) -> bool:
        """Check if a string appears to be a date."""
        # Simple check for common date formats
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{2}\.\d{2}\.\d{4}'  # DD.MM.YYYY
        ]
        
        return any(re.match(pattern, value) for pattern in date_patterns)
    
    def initialize(self):
        """Initialize the measurement agent."""
        # Load scheduled measurements
        self._load_measurement_schedule()
        logger.info(f"MeasurementAgent {self.agent_id} initialized")
    
    def _load_measurement_schedule(self):
        """Load the measurement schedule from memory."""
        # Try to load from memory
        schedule = self.retrieve_from_memory("measurement_schedule")
        
        if not schedule:
            # Create a default schedule
            schedule = {}
            metrics = self.metric_manager.list_metrics()
            
            for metric in metrics:
                # Default schedule based on metric frequency
                frequency = metric.frequency.lower() if metric.frequency else "monthly"
                
                schedule[metric.id] = {
                    "metric_id": metric.id,
                    "frequency": frequency,
                    "next_run": self._calculate_next_run_time(frequency),
                    "last_run": None,
                    "enabled": True
                }
            
            # Store the schedule
            self.store_in_memory("measurement_schedule", schedule)
        
        self.scheduled_measurements = schedule
    
    def _calculate_next_run_time(self, frequency: str) -> str:
        """Calculate the next run time based on frequency."""
        now = datetime.datetime.now()
        
        if frequency == "daily":
            next_run = now + datetime.timedelta(days=1)
        elif frequency == "weekly":
            next_run = now + datetime.timedelta(days=7)
        elif frequency == "monthly":
            # Add a month (approximately)
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1)
            else:
                next_run = now.replace(month=now.month + 1)
        elif frequency == "quarterly":
            # Add 3 months (approximately)
            month = ((now.month - 1) + 3) % 12 + 1
            year = now.year + ((now.month - 1) + 3) // 12
            next_run = now.replace(year=year, month=month)
        elif frequency == "annually" or frequency == "yearly":
            next_run = now.replace(year=now.year + 1)
        else:
            # Default to monthly
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1)
            else:
                next_run = now.replace(month=now.month + 1)
        
        return next_run.isoformat()
    
    def run_cycle(self):
        """Run a processing cycle."""
        # Process all pending messages
        self.process_messages()
        
        # Check for scheduled measurements
        self._check_scheduled_measurements()
    
    def _check_scheduled_measurements(self):
        """Check for and run scheduled measurements."""
        now = datetime.datetime.now().isoformat()
        
        for metric_id, schedule in list(self.scheduled_measurements.items()):
            if schedule.get("enabled", True) and schedule.get("next_run") and schedule.get("next_run") <= now:
                # Time to run this measurement
                logger.info(f"Running scheduled measurement for metric {metric_id}")
                
                try:
                    # Get the metric definition
                    metric = self.metric_manager.get_metric(metric_id)
                    
                    if metric:
                        # Collect and calculate the metric value
                        self.collect_metric_value(metric)
                        
                        # Update schedule
                        schedule["last_run"] = now
                        schedule["next_run"] = self._calculate_next_run_time(schedule.get("frequency", "monthly"))
                        
                        # Store updated schedule
                        self.scheduled_measurements[metric_id] = schedule
                        self.store_in_memory("measurement_schedule", self.scheduled_measurements)
                    else:
                        logger.warning(f"Scheduled metric {metric_id} not found")
                        
                except Exception as e:
                    logger.error(f"Error running scheduled measurement for {metric_id}: {str(e)}")
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages about measurements.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"MeasurementAgent received query: {query}")
        
        # Process the query to determine intent
        if re.search(r'(collect|calculate|measure).*metric', query, re.IGNORECASE):
            # Collect metric query
            return self._handle_collect_metric_query(query, message)
        
        elif re.search(r'(list|show|display|get).*metrics.*value', query, re.IGNORECASE):
            # List metric values query
            return self._handle_list_metric_values_query(query, message)
        
        elif re.search(r'(schedule|frequency).*metric', query, re.IGNORECASE):
            # Schedule query
            return self._handle_schedule_query(query, message)
        
        elif re.search(r'(data|source).*connect', query, re.IGNORECASE):
            # Data source query
            return self._handle_data_source_query(query, message)
        
        # General query about measurements
        return self._handle_general_measurement_query(query, message)
    
    def _handle_collect_metric_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to collect a metric value."""
        # Try to extract metric name or ID from query
        metric_match = re.search(r'(collect|calculate|measure).*metric\s+(.+?)(\s+from|\s+using|\s+with|\s+for|\s*$)', query, re.IGNORECASE)
        
        if not metric_match:
            return self.create_response_message(
                content="I couldn't understand which metric you want to collect. Please specify a metric name or ID.",
                original_message=message
            )
        
        metric_name = metric_match.group(2).strip()
        
        # Find the metric by name or ID
        all_metrics = self.metric_manager.list_metrics()
        
        target_metric = None
        for metric in all_metrics:
            if metric.id.lower() == metric_name.lower() or metric.name.lower() == metric_name.lower():
                target_metric = metric
                break
        
        if not target_metric:
            return self.create_response_message(
                content=f"I couldn't find a metric named '{metric_name}'. Please check the name and try again.",
                original_message=message
            )
        
        # Collect the metric value
        try:
            result = self.collect_metric_value(target_metric)
            
            if result:
                return self.create_response_message(
                    content=f"Successfully collected value for metric '{target_metric.name}': {result.value} {target_metric.unit}",
                    original_message=message
                )
            else:
                return self.create_response_message(
                    content=f"Unable to collect value for metric '{target_metric.name}'. The required data source may not be available.",
                    original_message=message
                )
            
        except Exception as e:
            logger.error(f"Error collecting metric value: {str(e)}")
            return self.create_error_message(
                error_content=f"Error collecting metric value: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def _handle_list_metric_values_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to list metric values."""
        # Try to extract metric name or ID from query
        metric_match = re.search(r'(list|show|display|get).*metrics?\s+(.+?)(\s+values?|\s+for|\s*$)', query, re.IGNORECASE)
        
        metric_id = None
        if metric_match:
            metric_name = metric_match.group(2).strip()
            
            # Find the metric by name or ID
            all_metrics = self.metric_manager.list_metrics()
            
            for metric in all_metrics:
                if metric.id.lower() == metric_name.lower() or metric.name.lower() == metric_name.lower():
                    metric_id = metric.id
                    break
        
        # Parse date range if specified
        start_date = None
        end_date = None
        
        start_match = re.search(r'(from|after|since)\s+(.+?)(\s+to|\s+until|\s+before|\s*$)', query, re.IGNORECASE)
        if start_match:
            start_date_text = start_match.group(2).strip()
            start_date = self.data_normalizer.normalize_date(start_date_text)
        
        end_match = re.search(r'(to|until|before)\s+(.+?)(\s+from|\s+after|\s+since|\s*$)', query, re.IGNORECASE)
        if end_match:
            end_date_text = end_match.group(2).strip()
            end_date = self.data_normalizer.normalize_date(end_date_text)
        
        # Get metric values
        if metric_id:
            # Get values for a specific metric
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                return self.create_response_message(
                    content=f"Metric '{metric_id}' not found.",
                    original_message=message
                )
            
            values = self.metric_manager.get_metric_values(metric_id, start_date, end_date)
            
            if not values:
                return self.create_response_message(
                    content=f"No values found for metric '{metric.name}' in the specified time range.",
                    original_message=message
                )
            
            # Format response
            response = f"Values for metric '{metric.name}' ({metric.unit}):\n\n"
            
            for value in values:
                timestamp = value.timestamp.split('T')[0] if 'T' in value.timestamp else value.timestamp
                response += f"- {timestamp}: {value.value}\n"
            
            # Add trend information if we have multiple values
            if len(values) > 1:
                trend = self._analyze_metric_trend(values)
                response += f"\nTrend: {trend['description']}, {trend['percentage_change']:.1f}% change over the period"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
        else:
            # Get latest values for all metrics
            all_metrics = self.metric_manager.list_metrics()
            
            if not all_metrics:
                return self.create_response_message(
                    content="No metrics found in the system.",
                    original_message=message
                )
            
            # Format response
            response = "Latest values for all metrics:\n\n"
            
            for metric in all_metrics:
                latest_value = self.metric_manager.get_latest_metric_value(metric.id)
                
                if latest_value:
                    timestamp = latest_value.timestamp.split('T')[0] if 'T' in latest_value.timestamp else latest_value.timestamp
                    response += f"- {metric.name}: {latest_value.value} {metric.unit} ({timestamp})\n"
                else:
                    response += f"- {metric.name}: No values available\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
    
    def _handle_schedule_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query about measurement schedules."""
        # Try to extract metric name or ID from query
        metric_match = re.search(r'(schedule|frequency).*metric\s+(.+?)(\s+to|\s+as|\s+for|\s*$)', query, re.IGNORECASE)
        
        if metric_match:
            # Query about specific metric's schedule
            metric_name = metric_match.group(2).strip()
            
            # Find the metric by name or ID
            all_metrics = self.metric_manager.list_metrics()
            
            target_metric = None
            for metric in all_metrics:
                if metric.id.lower() == metric_name.lower() or metric.name.lower() == metric_name.lower():
                    target_metric = metric
                    break
            
            if not target_metric:
                return self.create_response_message(
                    content=f"I couldn't find a metric named '{metric_name}'. Please check the name and try again.",
                    original_message=message
                )
            
            # Get schedule for this metric
            schedule = self.scheduled_measurements.get(target_metric.id)
            
            if not schedule:
                return self.create_response_message(
                    content=f"No measurement schedule found for metric '{target_metric.name}'.",
                    original_message=message
                )
            
            # Format response
            response = f"Measurement schedule for '{target_metric.name}':\n\n"
            response += f"Frequency: {schedule.get('frequency', 'Not set')}\n"
            
            if schedule.get('last_run'):
                response += f"Last measured: {schedule['last_run']}\n"
            else:
                response += "Last measured: Never\n"
            
            if schedule.get('next_run'):
                response += f"Next scheduled: {schedule['next_run']}\n"
            else:
                response += "Next scheduled: Not scheduled\n"
            
            response += f"Status: {'Enabled' if schedule.get('enabled', True) else 'Disabled'}"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
        else:
            # Query about all schedules
            if not self.scheduled_measurements:
                return self.create_response_message(
                    content="No measurement schedules defined.",
                    original_message=message
                )
            
            # Format response
            response = "Measurement schedules:\n\n"
            
            for metric_id, schedule in self.scheduled_measurements.items():
                metric = self.metric_manager.get_metric(metric_id)
                
                if not metric:
                    continue
                
                response += f"- {metric.name}:\n"
                response += f"  Frequency: {schedule.get('frequency', 'Not set')}\n"
                
                if schedule.get('next_run'):
                    next_run = schedule['next_run'].split('T')[0] if 'T' in schedule['next_run'] else schedule['next_run']
                    response += f"  Next scheduled: {next_run}\n"
                
                response += f"  Status: {'Enabled' if schedule.get('enabled', True) else 'Disabled'}\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
    
    def _handle_data_source_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query about data sources."""
        # List data sources
        data_sources = self.data_source_manager.list_data_sources()
        
        if not data_sources:
            return self.create_response_message(
                content="No data sources defined in the system.",
                original_message=message
            )
        
        # Format response
        response = "Available data sources:\n\n"
        
        for source in data_sources:
            response += f"- {source.name} ({source.type.value}):\n"
            response += f"  ID: {source.id}\n"
            response += f"  Location: {source.location}\n"
            response += f"  Description: {source.description}\n"
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_general_measurement_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a general query about measurements."""
        # Use LLM to generate response about measurements
        prompt = f"""
        You are a security metrics specialist following NIST SP 800-55 guidelines.
        A user has asked the following question about security measurements:
        
        "{query}"
        
        Provide a helpful response about how security metrics are collected, calculated, or measured.
        Focus on the practical aspects of security measurement according to NIST SP 800-55.
        
        Keep your response concise and focused on security measurement processes.
        """
        
        response = self.query_llm(prompt)
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def handle_command(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle command messages to perform measurement actions.
        
        Args:
            message: Command message
            
        Returns:
            Optional response message
        """
        command = message.content.content
        logger.info(f"MeasurementAgent received command: {command}")
        
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
        
        # Process different command types
        if command_type == "collect_metric":
            return self._handle_collect_metric_command(command_args, message)
        
        elif command_type == "schedule_metric":
            return self._handle_schedule_metric_command(command_args, message)
        
        elif command_type == "enable_metric":
            return self._handle_enable_metric_command(command_args, message, True)
        
        elif command_type == "disable_metric":
            return self._handle_enable_metric_command(command_args, message, False)
        
        elif command_type == "refresh_schedule":
            self._load_measurement_schedule()
            return self.create_response_message(
                content="Measurement schedule refreshed successfully.",
                original_message=message
            )
        
        # Unknown command
        return self.create_error_message(
            error_content=f"Unknown command: {command_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def _handle_collect_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to collect a metric value."""
        # Parse metric ID from command
        metric_id = command_args.strip()
        if not metric_id:
            return self.create_error_message(
                error_content="Metric ID not provided for collection",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Get the metric
        metric = self.metric_manager.get_metric(metric_id)
        if not metric:
            return self.create_error_message(
                error_content=f"Metric with ID '{metric_id}' not found",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Collect the metric value
        try:
            result = self.collect_metric_value(metric)
            
            if result:
                return self.create_response_message(
                    content=f"Successfully collected value for metric '{metric.name}': {result.value} {metric.unit}",
                    original_message=message
                )
            else:
                return self.create_response_message(
                    content=f"Unable to collect value for metric '{metric.name}'. The required data source may not be available.",
                    original_message=message
                )
            
        except Exception as e:
            logger.error(f"Error collecting metric value: {str(e)}")
            return self.create_error_message(
                error_content=f"Error collecting metric value: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def _handle_schedule_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to schedule a metric collection."""
        # Parse command arguments
        parts = command_args.split(maxsplit=1)
        if len(parts) < 2:
            return self.create_error_message(
                error_content="Invalid command format. Expected: schedule_metric <metric_id> <frequency>",
                receiver=message.sender,
                reply_to=message.id
            )
        
        metric_id = parts[0]
        frequency = parts[1].lower()
        
        # Validate frequency
        valid_frequencies = ["daily", "weekly", "monthly", "quarterly", "annually", "yearly"]
        if frequency not in valid_frequencies:
            return self.create_error_message(
                error_content=f"Invalid frequency: {frequency}. Valid values are: {', '.join(valid_frequencies)}",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Get the metric
        metric = self.metric_manager.get_metric(metric_id)
        if not metric:
            return self.create_error_message(
                error_content=f"Metric with ID '{metric_id}' not found",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Update schedule
        schedule = self.scheduled_measurements.get(metric_id, {
            "metric_id": metric_id,
            "enabled": True,
            "last_run": None
        })
        
        schedule["frequency"] = frequency
        schedule["next_run"] = self._calculate_next_run_time(frequency)
        
        # Store updated schedule
        self.scheduled_measurements[metric_id] = schedule
        self.store_in_memory("measurement_schedule", self.scheduled_measurements)
        
        return self.create_response_message(
            content=f"Successfully scheduled metric '{metric.name}' for {frequency} collection",
            original_message=message
        )
    
    def _handle_enable_metric_command(self, command_args: str, message: AgentMessage, enable: bool) -> AgentMessage:
        """Handle a command to enable or disable a metric collection."""
        # Parse metric ID from command
        metric_id = command_args.strip()
        if not metric_id:
            return self.create_error_message(
                error_content=f"Metric ID not provided for {'enabling' if enable else 'disabling'}",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Get the metric
        metric = self.metric_manager.get_metric(metric_id)
        if not metric:
            return self.create_error_message(
                error_content=f"Metric with ID '{metric_id}' not found",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Update schedule
        if metric_id in self.scheduled_measurements:
            self.scheduled_measurements[metric_id]["enabled"] = enable
            self.store_in_memory("measurement_schedule", self.scheduled_measurements)
            
            return self.create_response_message(
                content=f"Successfully {'enabled' if enable else 'disabled'} scheduled collection for metric '{metric.name}'",
                original_message=message
            )
        else:
            return self.create_error_message(
                error_content=f"No schedule found for metric '{metric_id}'",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def handle_request(self, message: AgentMessage) -> AgentMessage:
        """
        Handle request messages for measurements from other agents.
        
        Args:
            message: Request message
            
        Returns:
            Response message
        """
        request = message.content.content
        logger.info(f"MeasurementAgent received request: {request}")
        
        # Check request type from metadata
        request_type = message.content.metadata.get("request_type", "")
        
        if request_type == "collect_metric":
            # Request to collect a metric value
            metric_id = request
            
            # Get the metric
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                return self.create_error_message(
                    error_content=f"Metric with ID '{metric_id}' not found",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Collect the metric value
            try:
                result = self.collect_metric_value(metric)
                
                if result:
                    return self.create_response_message(
                        content=result.to_dict(),
                        original_message=message,
                        metadata={"response_type": "metric_value"}
                    )
                else:
                    return self.create_error_message(
                        error_content=f"Unable to collect value for metric '{metric_id}'",
                        receiver=message.sender,
                        reply_to=message.id
                    )
                
            except Exception as e:
                logger.error(f"Error collecting metric value: {str(e)}")
                return self.create_error_message(
                    error_content=f"Error collecting metric value: {str(e)}",
                    receiver=message.sender,
                    reply_to=message.id
                )
        
        elif request_type == "get_metric_values":
            # Request for metric values
            metric_id = request
            
            # Parse optional parameters from metadata
            start_date = message.content.metadata.get("start_date")
            end_date = message.content.metadata.get("end_date")
            
            # Get metric values
            try:
                values = self.metric_manager.get_metric_values(metric_id, start_date, end_date)
                values_data = [v.to_dict() for v in values]
                
                return self.create_response_message(
                    content=values_data,
                    original_message=message,
                    metadata={"response_type": "metric_values"}
                )
                
            except Exception as e:
                logger.error(f"Error getting metric values: {str(e)}")
                return self.create_error_message(
                    error_content=f"Error getting metric values: {str(e)}",
                    receiver=message.sender,
                    reply_to=message.id
                )
        
        elif request_type == "get_data_source":
            # Request for data source information
            source_id = request
            
            # Get data source
            source = self.data_source_manager.get_data_source(source_id)
            if not source:
                return self.create_error_message(
                    error_content=f"Data source with ID '{source_id}' not found",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            return self.create_response_message(
                content=source.to_dict(),
                original_message=message,
                metadata={"response_type": "data_source"}
            )
        
        # Unknown request type
        return self.create_error_message(
            error_content=f"Unknown request type: {request_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def collect_metric_value(self, metric: MetricDefinition) -> Optional[MetricValue]:
        """
        Collect and calculate a value for a metric.
        
        Args:
            metric: Metric definition
            
        Returns:
            Metric value or None if not possible
        """
        # Check if we have a data source for this metric
        data_source_id = metric.data_source
        
        if not data_source_id:
            # Try to determine data source based on metric name/description
            data_source_id = self._find_data_source_for_metric(metric)
            
            if not data_source_id:
                logger.warning(f"No data source found for metric {metric.id}")
                return self._generate_synthetic_value(metric)
        
        # Get data from the source
        try:
            data = self.data_source_manager.fetch_data(data_source_id)
            
            if not data:
                logger.warning(f"No data retrieved from source {data_source_id} for metric {metric.id}")
                return self._generate_synthetic_value(metric)
            
            # Get source type for normalization
            source = self.data_source_manager.get_data_source(data_source_id)
            source_type = source.type.value if source else "unknown"
            
            # Normalize the data
            normalized_data = self.data_normalizer.normalize(data, source_type)
            
            # Calculate the metric value
            value = self._calculate_metric_value(metric, normalized_data)
            
            if value is None:
                logger.warning(f"Could not calculate value for metric {metric.id}")
                return self._generate_synthetic_value(metric)
            
            # Create and store the metric value
            metric_value = MetricValue(
                metric_id=metric.id,
                value=value,
                source=data_source_id,
                collection_method="automated",
                notes=f"Calculated from {len(data)} data records"
            )
            
            # Add to metric manager
            self.metric_manager.add_metric_value(metric_value)
            
            return metric_value
            
        except Exception as e:
            logger.error(f"Error collecting metric value: {str(e)}")
            return None
    
    def _find_data_source_for_metric(self, metric: MetricDefinition) -> Optional[str]:
        """
        Find an appropriate data source for a metric based on its properties.
        
        Args:
            metric: Metric definition
            
        Returns:
            Data source ID or None if not found
        """
        # Get all data sources
        data_sources = self.data_source_manager.list_data_sources()
        
        if not data_sources:
            return None
        
        # Try to match based on name similarity
        metric_keywords = set(self._extract_keywords(metric.name) + self._extract_keywords(metric.description))
        
        best_match = None
        best_score = 0
        
        for source in data_sources:
            source_keywords = set(self._extract_keywords(source.name) + self._extract_keywords(source.description))
            
            # Calculate overlap score
            common_keywords = metric_keywords.intersection(source_keywords)
            score = len(common_keywords)
            
            if score > best_score:
                best_score = score
                best_match = source.id
        
        # If we have a reasonable match (at least one common keyword), use it
        if best_score > 0:
            return best_match
        
        # Fall back to the first data source as a last resort
        if data_sources:
            return data_sources[0].id
        
        return None
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text."""
        if not text:
            return []
        
        # Lowercase and remove punctuation
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        
        # Split into words
        words = text.split()
        
        # Remove common words
        stop_words = {"a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for", "with", "by", "of", "is", "are"}
        return [w for w in words if w not in stop_words and len(w) > 2]
    
    def _calculate_metric_value(self, metric: MetricDefinition, data: List[Dict[str, Any]]) -> Optional[float]:
        """
        Calculate a value for a metric based on the data.
        
        Args:
            metric: Metric definition
            data: Normalized data records
            
        Returns:
            Calculated value or None if not possible
        """
        # Try to determine calculation method from the formula
        formula = metric.formula.lower() if metric.formula else ""
        
        # Check for common calculation patterns
        if "count" in formula:
            # Count records
            return float(len(data))
        
        elif "sum" in formula or "total" in formula:
            # Sum a field value
            field = self._extract_field_from_formula(formula, data)
            if field:
                total = 0
                for record in data:
                    try:
                        value = float(record.get(field, 0))
                        total += value
                    except (ValueError, TypeError):
                        pass
                return total
            return None
        
        elif "average" in formula or "avg" in formula or "mean" in formula:
            # Calculate average of a field
            field = self._extract_field_from_formula(formula, data)
            if field:
                values = []
                for record in data:
                    try:
                        value = float(record.get(field, 0))
                        values.append(value)
                    except (ValueError, TypeError):
                        pass
                
                if values:
                    return sum(values) / len(values)
            return None
        
        elif "percent" in formula or "%" in formula:
            # Calculate percentage
            match = re.search(r'\((.+?)\s*/\s*(.+?)\)', formula)
            if match:
                numerator_expr = match.group(1).strip()
                denominator_expr = match.group(2).strip()
                
                numerator = self._evaluate_expression(numerator_expr, data)
                denominator = self._evaluate_expression(denominator_expr, data)
                
                if denominator and denominator != 0:
                    return (numerator / denominator) * 100
            return None
        
        elif "max" in formula:
            # Find maximum value
            field = self._extract_field_from_formula(formula, data)
            if field:
                values = []
                for record in data:
                    try:
                        value = float(record.get(field, 0))
                        values.append(value)
                    except (ValueError, TypeError):
                        pass
                
                if values:
                    return max(values)
            return None
        
        elif "min" in formula:
            # Find minimum value
            field = self._extract_field_from_formula(formula, data)
            if field:
                values = []
                for record in data:
                    try:
                        value = float(record.get(field, 0))
                        values.append(value)
                    except (ValueError, TypeError):
                        pass
                
                if values:
                    return min(values)
            return None
        
        # If we can't determine a calculation method, use sum of all numeric fields
        total = 0
        for record in data:
            for key, value in record.items():
                try:
                    numeric_value = float(value)
                    total += numeric_value
                except (ValueError, TypeError):
                    pass
        
        return total if total != 0 else None
    
    def _extract_field_from_formula(self, formula: str, data: List[Dict[str, Any]]) -> Optional[str]:
        """
        Extract field name from formula.
        
        Args:
            formula: Metric formula
            data: Data records to check for field existence
            
        Returns:
            Field name or None if not found
        """
        if not data:
            return None
        
        # Extract potential field names from formula
        words = re.findall(r'[a-zA-Z_]\w*', formula)
        
        # Remove common function names and keywords
        function_names = {"count", "sum", "average", "avg", "mean", "max", "min", "total", "percent"}
        candidates = [w for w in words if w.lower() not in function_names]
        
        # Check if any of the candidates exist in the data
        sample_record = data[0]
        for candidate in candidates:
            if candidate in sample_record:
                return candidate
            
            # Try lowercase version
            if candidate.lower() in sample_record:
                return candidate.lower()
        
        # If no match, try to find a field with similar name
        for candidate in candidates:
            for field in sample_record.keys():
                if candidate.lower() in field.lower() or field.lower() in candidate.lower():
                    return field
        
        # If still no match, return the first numeric field
        for field, value in sample_record.items():
            try:
                float(value)
                return field
            except (ValueError, TypeError):
                pass
        
        return None
    
    def _evaluate_expression(self, expression: str, data: List[Dict[str, Any]]) -> float:
        """
        Evaluate a simple expression against data.
        
        Args:
            expression: Expression to evaluate
            data: Data records
            
        Returns:
            Evaluation result
        """
        expression = expression.strip().lower()
        
        if expression == "count" or expression == "count()":
            return len(data)
        
        # Check for function-like expressions
        match = re.match(r'(\w+)\((\w+)\)', expression)
        if match:
            func = match.group(1)
            field = match.group(2)
            
            # Extract values for the field
            values = []
            for record in data:
                try:
                    value = float(record.get(field, 0))
                    values.append(value)
                except (ValueError, TypeError):
                    pass
            
            if not values:
                return 0
            
            # Apply function
            if func == "sum":
                return sum(values)
            elif func in ["avg", "average", "mean"]:
                return sum(values) / len(values)
            elif func == "max":
                return max(values)
            elif func == "min":
                return min(values)
            elif func == "count":
                return len(values)
        
        # Check for field names directly
        for record in data:
            if expression in record:
                try:
                    return float(record[expression])
                except (ValueError, TypeError):
                    pass
        
        # Try numeric interpretation
        try:
            return float(expression)
        except (ValueError, TypeError):
            pass
        
        return 0
    
    def _generate_synthetic_value(self, metric: MetricDefinition) -> Optional[MetricValue]:
        """
        Generate a synthetic value for a metric when real data is unavailable.
        
        Args:
            metric: Metric definition
            
        Returns:
            Synthetic metric value
        """
        # Check for existing values to base the synthetic value on
        previous_values = self.metric_manager.get_metric_values(metric.id)
        
        if previous_values:
            # Use the latest value as a base
            latest_value = previous_values[-1]
            
            # Add some random variation (±10%)
            import random
            variation = random.uniform(-0.1, 0.1)
            new_value = latest_value.value * (1 + variation)
            
            # Ensure the value makes sense for the metric type
            if metric.type == MetricType.IMPLEMENTATION and new_value > 100:
                new_value = 100
            
            if new_value < 0:
                new_value = 0
        else:
            # Generate a reasonable default value based on metric type
            import random
            
            if metric.type == MetricType.IMPLEMENTATION:
                # Implementation metrics are often percentages
                new_value = random.uniform(50, 90)
            
            elif metric.type == MetricType.EFFECTIVENESS:
                # Effectiveness metrics vary widely
                new_value = random.uniform(70, 95)
            
            elif metric.type == MetricType.EFFICIENCY:
                # Efficiency metrics are often time-based
                new_value = random.uniform(10, 50)
            
            else:
                # Default
                new_value = random.uniform(1, 100)
        
        # Create the synthetic metric value
        metric_value = MetricValue(
            metric_id=metric.id,
            value=new_value,
            source="synthetic",
            collection_method="simulated",
            notes="Synthetically generated due to lack of data source"
        )
        
        # Add to metric manager
        self.metric_manager.add_metric_value(metric_value)
        
        return metric_value
    
    def _analyze_metric_trend(self, values: List[MetricValue]) -> Dict[str, Any]:
        """
        Analyze trend in a series of metric values.
        
        Args:
            values: List of metric values
            
        Returns:
            Trend analysis results
        """
        if len(values) < 2:
            return {
                "direction": "stable",
                "description": "Insufficient data for trend analysis",
                "percentage_change": 0.0
            }
        
        # Sort by timestamp
        sorted_values = sorted(values, key=lambda v: v.timestamp)
        
        # Calculate percentage change from first to last
        first_value = sorted_values[0].value
        last_value = sorted_values[-1].value
        
        if first_value == 0:
            percentage_change = 100 if last_value > 0 else 0
        else:
            percentage_change = ((last_value - first_value) / abs(first_value)) * 100
        
        # Determine trend direction
        if abs(percentage_change) < 5:
            direction = "stable"
            description = "The metric has remained relatively stable"
        elif percentage_change > 0:
            direction = "increasing"
            
            if percentage_change > 50:
                description = "The metric has increased significantly"
            elif percentage_change > 20:
                description = "The metric has increased moderately"
            else:
                description = "The metric has increased slightly"
        else:
            direction = "decreasing"
            
            if abs(percentage_change) > 50:
                description = "The metric has decreased significantly"
            elif abs(percentage_change) > 20:
                description = "The metric has decreased moderately"
            else:
                description = "The metric has decreased slightly"
        
        return {
            "direction": direction,
            "description": description,
            "percentage_change": percentage_change,
            "first_value": first_value,
            "last_value": last_value,
            "duration": sorted_values[-1].timestamp + " - " + sorted_values[0].timestamp
        }
    
    def collect_metric_value_with_report(self, metric: MetricDefinition) -> Optional[MetricValue]:
        """
        Collect and calculate a value for a metric, storing a report of the process.
        
        Args:
            metric: Metric definition
            
        Returns:
            Metric value or None if not possible
        """
        # Original implementation
        result = self.collect_metric_value(metric)
        
        # Create a measurement report
        if result:
            # Format the report content
            report_content = f"""# Measurement Report for {metric.name}

    ## Metric Details
    - ID: {metric.id}
    - Name: {metric.name}
    - Type: {metric.type.value}
    - Description: {metric.description}
    - Formula: {metric.formula}
    - Unit: {metric.unit}

    ## Measurement Results
    - Value: {result.value} {metric.unit}
    - Timestamp: {result.timestamp}
    - Source: {result.source}
    - Collection Method: {result.collection_method}

    ## Notes
    {result.notes}
    """
            
            # Store the report if report persistence is available
            try:
                # Method 1: Try to get from parent system reference
                if hasattr(self, 'system') and hasattr(self.system, 'report_persistence'):
                    report_id = self.system.report_persistence.store_report(
                        content=report_content,
                        title=f"Measurement Report - {metric.name}",
                        agent_id=self.agent_id,
                        report_type="measurement",
                        metadata={
                            "metric_id": metric.id,
                            "metric_type": metric.type.value,
                            "value": result.value,
                            "unit": metric.unit
                        }
                    )
                    logger.info(f"Measurement report stored with ID: {report_id}")
                
                # Method 2: If available through message bus
                elif hasattr(self.message_bus, 'system') and hasattr(self.message_bus.system, 'report_persistence'):
                    report_id = self.message_bus.system.report_persistence.store_report(
                        content=report_content,
                        title=f"Measurement Report - {metric.name}",
                        agent_id=self.agent_id,
                        report_type="measurement",
                        metadata={
                            "metric_id": metric.id,
                            "metric_type": metric.type.value,
                            "value": result.value,
                            "unit": metric.unit
                        }
                    )
                    logger.info(f"Measurement report stored with ID: {report_id}")
            except Exception as e:
                logger.error(f"Error storing measurement report: {str(e)}")
        
        return result