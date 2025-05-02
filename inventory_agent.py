#!/usr/bin/env python3
"""
Security Capability Measurement Program - Inventory Agent Implementation

This module implements the Inventory Agent which is responsible for scanning, 
classifying, and managing security metrics according to NIST SP 800-55.
"""

import re
import logging
import datetime
from typing import Dict, List, Any, Optional, Tuple

# Import components from previous milestones
from environmental import MessageType, MessageContent, AgentMessage
from base_structure import BaseAgent, MessageBus
from data_management import MetricType, MetricStatus, MetricDefinition, MetricManager

logger = logging.getLogger('security_measurement')

class InventoryAgent(BaseAgent):
    """
    Agent responsible for managing the inventory of security metrics.
    Handles scanning, classification, and gap analysis of security metrics
    based on NIST SP 800-55 framework.
    """
    
    def __init__(self, agent_id: str, agent_type: str, description: str, message_bus: MessageBus,
                 model_name: str = "llama3.2:latest", temperature: float = 0.1,
                 system_prompt: str = None):
        """Initialize the inventory agent."""
        super().__init__(agent_id, agent_type, description, message_bus, model_name, temperature, system_prompt)
        
        # Initialize metric manager
        self.metric_manager = MetricManager()
        
        # Keyword patterns for classification
        self.classification_patterns = {
            MetricType.IMPLEMENTATION: [
                r'implement(ation|ed|ing)?', r'deploy(ed|ment)?', r'install(ed|ation)?',
                r'configur(e|ed|ation)', r'policy', r'procedure', r'control', r'compliance',
                r'coverage', r'complete(d|ness)', r'presence', r'existence'
            ],
            MetricType.EFFECTIVENESS: [
                r'effective(ness)?', r'success(ful)?', r'detect(ion|ed)?', r'prevent(ion|ed)?',
                r'reduce', r'impact', r'incident', r'breach', r'compromise', r'intrusion',
                r'response', r'time to', r'mean time', r'rate', r'accuracy'
            ],
            MetricType.EFFICIENCY: [
                r'efficien(cy|t)', r'cost', r'resource', r'time', r'staff', r'effort',
                r'automat(e|ed|ion)', r'streamline(d)?', r'optimize(d)?', r'productivity',
                r'utilization', r'throughput', r'performance'
            ],
            MetricType.IMPACT: [
                r'impact', r'business', r'operation', r'financial', r'reputation',
                r'customer', r'revenue', r'loss', r'damage', r'roi', r'return on',
                r'value', r'benefit', r'strategic', r'objective', r'goal'
            ]
        }
        
        # Subscribe to relevant message types
        self.message_bus.subscribe(self.agent_id, [
            MessageType.QUERY.value,
            MessageType.REQUEST.value,
            MessageType.COMMAND.value
        ])
    
    def initialize(self):
        """Initialize the inventory agent."""
        # Load existing metrics
        self.refresh_metrics_inventory()
        logger.info(f"InventoryAgent {self.agent_id} initialized")
    
    def refresh_metrics_inventory(self):
        """Refresh the metrics inventory from the metric manager."""
        metrics = self.metric_manager.list_metrics()
        metrics_by_type = {
            MetricType.IMPLEMENTATION: [],
            MetricType.EFFECTIVENESS: [],
            MetricType.EFFICIENCY: [],
            MetricType.IMPACT: []
        }
        
        # Organize metrics by type
        for metric in metrics:
            if metric.type in metrics_by_type:
                metrics_by_type[metric.type].append(metric)
        
        # Store in memory
        self.store_in_memory("metrics_inventory", metrics_by_type)
        logger.debug(f"Refreshed metrics inventory with {len(metrics)} metrics")
    
    def run_cycle(self):
        """Run a processing cycle."""
        # Process all pending messages
        self.process_messages()
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages about the metrics inventory.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"InventoryAgent received query: {query}")
        
        # Process the query to determine intent
        if re.search(r'(list|show|display|get).*metrics', query, re.IGNORECASE):
            # List metrics query
            return self._handle_list_metrics_query(query, message)
        
        elif re.search(r'(classify|categorize|category|type).*metric', query, re.IGNORECASE):
            # Classify metric query
            return self._handle_classify_metric_query(query, message)
        
        elif re.search(r'(gap|missing|needed|require).*metrics', query, re.IGNORECASE):
            # Gap analysis query
            return self._handle_gap_analysis_query(query, message)
        
        elif re.search(r'(add|create|new).*metric', query, re.IGNORECASE):
            # Add metric query - delegate to handle_command
            return self.handle_command(AgentMessage(
                sender=message.sender,
                receiver=self.agent_id,
                content=MessageContent(
                    type=MessageType.COMMAND,
                    content=f"add_metric {query}"
                ),
                reply_to=message.id
            ))
        
        # General query about metrics
        return self._handle_general_metrics_query(query, message)
    
    def _handle_list_metrics_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to list metrics."""
        metrics_by_type = self.retrieve_from_memory("metrics_inventory")
        
        # Check if query specifies a specific type
        metric_type = None
        for type_enum in MetricType:
            if re.search(rf'{type_enum.value}', query, re.IGNORECASE):
                metric_type = type_enum
                break
        
        if metric_type:
            # List metrics of a specific type
            metrics = metrics_by_type.get(metric_type, [])
            response = f"Found {len(metrics)} {metric_type.value} metrics:\n\n"
            
            for metric in metrics:
                response += f"- {metric.name}: {metric.description}\n"
            
        else:
            # List all metrics
            total_count = sum(len(metrics) for metrics in metrics_by_type.values())
            response = f"Found {total_count} metrics in the inventory:\n\n"
            
            for type_enum, metrics in metrics_by_type.items():
                response += f"{type_enum.value.capitalize()} Metrics ({len(metrics)}):\n"
                for metric in metrics:
                    response += f"- {metric.name}\n"
                response += "\n"
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_classify_metric_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to classify a metric."""
        # Extract metric information from query
        metric_name = None
        metric_desc = None
        
        # Try to find metric name pattern: "classify metric X"
        name_match = re.search(r'(classify|categorize).*metric\s+(.+?)(\s+as|\s+with|\s+in|$)', query, re.IGNORECASE)
        if name_match:
            metric_name = name_match.group(2).strip()
        
        # Try to find description pattern: "with description X"
        desc_match = re.search(r'description\s+(.+?)(\s+as|\s+with|\s+in|$)', query, re.IGNORECASE)
        if desc_match:
            metric_desc = desc_match.group(1).strip()
        
        if not metric_name and not metric_desc:
            return self.create_response_message(
                content="I couldn't understand which metric you want to classify. Please provide a metric name or description.",
                original_message=message
            )
        
        # Perform classification
        metric_info = metric_name or ""
        if metric_desc:
            metric_info += f": {metric_desc}"
        
        classification = self.classify_metric(metric_info)
        
        # Create response
        response = f"I've classified the metric '{metric_name or 'provided'}' as a {classification.value.upper()} metric based on NIST SP 800-55.\n\n"
        response += f"This category is for metrics that measure the {self._get_type_description(classification)}."
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_gap_analysis_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to perform gap analysis."""
        # Refresh metrics inventory
        self.refresh_metrics_inventory()
        metrics_by_type = self.retrieve_from_memory("metrics_inventory")
        
        # Get counts by type
        type_counts = {t: len(metrics) for t, metrics in metrics_by_type.items()}
        total_count = sum(type_counts.values())
        
        # Calculate percentages
        type_percentages = {t: (count / total_count * 100) if total_count > 0 else 0 
                          for t, count in type_counts.items()}
        
        # Identify gaps based on NIST SP 800-55 recommendations
        # (Typical distribution: Implementation 40%, Effectiveness 30%, Efficiency 20%, Impact 10%)
        gaps = []
        
        if type_percentages.get(MetricType.IMPLEMENTATION, 0) < 30:
            gaps.append("Implementation")
        
        if type_percentages.get(MetricType.EFFECTIVENESS, 0) < 20:
            gaps.append("Effectiveness")
        
        if type_percentages.get(MetricType.EFFICIENCY, 0) < 10:
            gaps.append("Efficiency")
        
        if type_percentages.get(MetricType.IMPACT, 0) < 5:
            gaps.append("Impact")
        
        # Create response
        response = "Gap Analysis of Security Metrics:\n\n"
        response += f"Current Metrics Distribution (Total: {total_count}):\n"
        
        for type_enum in MetricType:
            count = type_counts.get(type_enum, 0)
            percentage = type_percentages.get(type_enum, 0)
            response += f"- {type_enum.value.capitalize()}: {count} metrics ({percentage:.1f}%)\n"
        
        response += "\nIdentified Gaps:\n"
        
        if gaps:
            for gap in gaps:
                response += f"- {gap} metrics coverage is below recommended thresholds\n"
        else:
            response += "- No significant gaps identified based on NIST SP 800-55 recommendations\n"
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_general_metrics_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a general query about metrics."""
        # Use LLM to generate response about metrics
        prompt = f"""
        You are a security metrics specialist following NIST SP 800-55 guidelines.
        A user has asked the following question about security metrics:
        
        "{query}"
        
        Provide a helpful response based on the NIST SP 800-55 framework, which categorizes
        security metrics into:
        
        1. Implementation metrics (tracking progress of security controls)
        2. Effectiveness metrics (evaluating how well controls are working)
        3. Efficiency metrics (examining timeliness and resource usage)
        4. Impact metrics (articulating business impact of security measures)
        
        Keep your response concise and focused on security metrics.
        """
        
        response = self.query_llm(prompt)
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def handle_command(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle command messages to perform actions on metrics.
        
        Args:
            message: Command message
            
        Returns:
            Optional response message
        """
        command = message.content.content
        logger.info(f"InventoryAgent received command: {command}")
        
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
        if command_type == "add_metric":
            return self._handle_add_metric_command(command_args, message)
        
        elif command_type == "update_metric":
            return self._handle_update_metric_command(command_args, message)
        
        elif command_type == "delete_metric":
            return self._handle_delete_metric_command(command_args, message)
        
        elif command_type == "refresh_inventory":
            self.refresh_metrics_inventory()
            return self.create_response_message(
                content="Metrics inventory refreshed successfully.",
                original_message=message
            )
        
        # Unknown command
        return self.create_error_message(
            error_content=f"Unknown command: {command_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def _handle_add_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to add a new metric."""
        # Use LLM to parse metric details from natural language
        prompt = f"""
        You are a security metrics specialist following NIST SP 800-55 guidelines.
        Parse the following description into a structured security metric definition:
        
        "{command_args}"
        
        Extract and provide only the following details in JSON format without any additional text:
        {{
            "id": "a unique ID for the metric (lowercase with underscores)",
            "name": "the metric name",
            "description": "a concise description of the metric",
            "type": "the metric type (implementation, effectiveness, efficiency, or impact)",
            "formula": "how the metric is calculated",
            "unit": "the unit of measurement"
        }}
        
        If any fields cannot be determined from the input, use reasonable defaults.
        Respond with ONLY valid JSON and nothing else.
        """
        
        # Query LLM to extract metric details
        try:
            llm_response = self.query_llm(prompt)
            
            # Extract JSON from the response
            import json
            import re
            
            # Try to find JSON in the response
            json_match = re.search(r'({.*})', llm_response, re.DOTALL)
            if json_match:
                llm_response = json_match.group(1)
            
            metric_data = json.loads(llm_response)
            
            # Create metric definition
            metric_type = MetricType(metric_data.get("type", "implementation"))
            metric = MetricDefinition(
                id=metric_data.get("id", f"metric_{int(datetime.datetime.now().timestamp())}"),
                name=metric_data.get("name", "Unnamed Metric"),
                description=metric_data.get("description", ""),
                type=metric_type,
                formula=metric_data.get("formula", ""),
                unit=metric_data.get("unit", "")
            )
            
            # Add the metric
            if self.metric_manager.create_metric(metric):
                # Refresh inventory
                self.refresh_metrics_inventory()
                
                return self.create_response_message(
                    content=f"Successfully added new {metric_type.value} metric: {metric.name}",
                    original_message=message
                )
            else:
                return self.create_error_message(
                    error_content=f"Failed to add metric. Metric with ID '{metric.id}' may already exist.",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
        except Exception as e:
            logger.error(f"Error adding metric: {str(e)}")
            return self.create_error_message(
                error_content=f"Error adding metric: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def _handle_update_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to update an existing metric."""
        # Parse metric ID from command
        parts = command_args.split(maxsplit=1)
        if not parts:
            return self.create_error_message(
                error_content="Metric ID not provided for update",
                receiver=message.sender,
                reply_to=message.id
            )
        
        metric_id = parts[0]
        update_text = parts[1] if len(parts) > 1 else ""
        
        # Get existing metric
        metric = self.metric_manager.get_metric(metric_id)
        if not metric:
            return self.create_error_message(
                error_content=f"Metric with ID '{metric_id}' not found",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Use LLM to parse update details
        prompt = f"""
        You are a security metrics specialist following NIST SP 800-55 guidelines.
        Parse the following update request for an existing security metric:
        
        Existing Metric:
        - ID: {metric.id}
        - Name: {metric.name}
        - Description: {metric.description}
        - Type: {metric.type.value}
        - Formula: {metric.formula}
        - Unit: {metric.unit}
        
        Update Request:
        "{update_text}"
        
        Extract changes to be made to the metric. Provide only a JSON object with the fields that should be updated:
        {{
            "name": "new name if changed",
            "description": "new description if changed",
            "type": "new type if changed (implementation, effectiveness, efficiency, or impact)",
            "formula": "new formula if changed",
            "unit": "new unit if changed",
            "status": "new status if changed (active, inactive, deprecated, proposed, under_review)"
        }}
        
        Only include fields that should be changed based on the update request.
        Respond with ONLY valid JSON and nothing else.
        """
        
        # Query LLM to extract update details
        try:
            llm_response = self.query_llm(prompt)
            
            # Extract JSON from the response
            import json
            import re
            
            # Try to find JSON in the response
            json_match = re.search(r'({.*})', llm_response, re.DOTALL)
            if json_match:
                llm_response = json_match.group(1)
            
            update_data = json.loads(llm_response)
            
            # Update metric fields
            if "name" in update_data:
                metric.name = update_data["name"]
            
            if "description" in update_data:
                metric.description = update_data["description"]
            
            if "type" in update_data:
                metric.type = MetricType(update_data["type"])
            
            if "formula" in update_data:
                metric.formula = update_data["formula"]
            
            if "unit" in update_data:
                metric.unit = update_data["unit"]
            
            if "status" in update_data:
                metric.status = MetricStatus(update_data["status"])
            
            # Update the metric
            if self.metric_manager.update_metric(metric):
                # Refresh inventory
                self.refresh_metrics_inventory()
                
                return self.create_response_message(
                    content=f"Successfully updated metric: {metric.name}",
                    original_message=message
                )
            else:
                return self.create_error_message(
                    error_content=f"Failed to update metric with ID '{metric.id}'.",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
        except Exception as e:
            logger.error(f"Error updating metric: {str(e)}")
            return self.create_error_message(
                error_content=f"Error updating metric: {str(e)}",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def _handle_delete_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to delete a metric."""
        # Parse metric ID from command
        metric_id = command_args.strip()
        if not metric_id:
            return self.create_error_message(
                error_content="Metric ID not provided for deletion",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Delete the metric
        if self.metric_manager.delete_metric(metric_id):
            # Refresh inventory
            self.refresh_metrics_inventory()
            
            return self.create_response_message(
                content=f"Successfully deleted metric with ID '{metric_id}'",
                original_message=message
            )
        else:
            return self.create_error_message(
                error_content=f"Failed to delete metric with ID '{metric_id}'",
                receiver=message.sender,
                reply_to=message.id
            )
    
    def handle_request(self, message: AgentMessage) -> AgentMessage:
        """
        Handle request messages for information from other agents.
        
        Args:
            message: Request message
            
        Returns:
            Response message
        """
        request = message.content.content
        logger.info(f"InventoryAgent received request: {request}")
        
        # Check request type from metadata
        request_type = message.content.metadata.get("request_type", "")
        
        if request_type == "metrics_list":
            # Request for metrics list
            metrics_by_type = self.retrieve_from_memory("metrics_inventory")
            
            # Get metrics of a specific type if specified
            metric_type = message.content.metadata.get("metric_type")
            
            if metric_type:
                try:
                    metric_type_enum = MetricType(metric_type)
                    metrics = metrics_by_type.get(metric_type_enum, [])
                    metrics_data = [m.to_dict() for m in metrics]
                except ValueError:
                    return self.create_error_message(
                        error_content=f"Invalid metric type: {metric_type}",
                        receiver=message.sender,
                        reply_to=message.id
                    )
            else:
                # Get all metrics
                metrics_data = []
                for metrics in metrics_by_type.values():
                    metrics_data.extend([m.to_dict() for m in metrics])
            
            return self.create_response_message(
                content=metrics_data,
                original_message=message,
                metadata={"response_type": "metrics_list"}
            )
        
        elif request_type == "classify_metric":
            # Request to classify a metric
            metric_text = request
            classification = self.classify_metric(metric_text)
            
            return self.create_response_message(
                content=classification.value,
                original_message=message,
                metadata={"response_type": "classification"}
            )
        
        elif request_type == "gap_analysis":
            # Request for gap analysis
            gaps = self.identify_gaps()
            
            return self.create_response_message(
                content=gaps,
                original_message=message,
                metadata={"response_type": "gap_analysis"}
            )
        
        # Unknown request type
        return self.create_error_message(
            error_content=f"Unknown request type: {request_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def classify_metric(self, metric_text: str) -> MetricType:
        """
        Classify a metric based on its description.
        
        Args:
            metric_text: Text describing the metric
            
        Returns:
            Classified metric type
        """
        # Convert to lowercase for case-insensitive matching
        metric_text = metric_text.lower()
        
        # Count pattern matches for each type
        match_counts = {}
        
        for metric_type, patterns in self.classification_patterns.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, metric_text, re.IGNORECASE):
                    match_count += 1
            
            match_counts[metric_type] = match_count
        
        # Find the type with the most matches
        best_type = max(match_counts.items(), key=lambda x: x[1])[0]
        
        # If no matches found, use LLM for classification
        if match_counts[best_type] == 0:
            prompt = f"""
            You are a security metrics specialist following NIST SP 800-55 guidelines.
            Classify the following security metric into one of these categories:
            - implementation (measuring control implementation progress)
            - effectiveness (measuring how well controls are working)
            - efficiency (measuring resource usage and timeliness)
            - impact (measuring business impact of security)
            
            Metric: "{metric_text}"
            
            Respond with ONLY ONE WORD - the category name.
            """
            
            llm_response = self.query_llm(prompt).strip().lower()
            
            # Map LLM response to MetricType
            for metric_type in MetricType:
                if metric_type.value in llm_response:
                    return metric_type
            
            # Default to UNKNOWN if LLM response cannot be mapped
            return MetricType.UNKNOWN
        
        return best_type
    
    def identify_gaps(self) -> Dict[str, Any]:
        """
        Identify gaps in the metrics inventory.
        
        Returns:
            Dictionary with gap analysis results
        """
        # Refresh metrics inventory
        self.refresh_metrics_inventory()
        metrics_by_type = self.retrieve_from_memory("metrics_inventory")
        
        # Get counts by type
        type_counts = {t: len(metrics) for t, metrics in metrics_by_type.items()}
        total_count = sum(type_counts.values())
        
        # Calculate percentages
        type_percentages = {t: (count / total_count * 100) if total_count > 0 else 0 
                          for t, count in type_counts.items()}
        
        # Identify gaps based on NIST SP 800-55 recommendations
        gaps = {}
        
        for metric_type in MetricType:
            percentage = type_percentages.get(metric_type, 0)
            count = type_counts.get(metric_type, 0)
            
            # Determine gap severity
            if metric_type == MetricType.IMPLEMENTATION and percentage < 30:
                severity = "high" if percentage < 20 else "medium"
            elif metric_type == MetricType.EFFECTIVENESS and percentage < 20:
                severity = "high" if percentage < 10 else "medium"
            elif metric_type == MetricType.EFFICIENCY and percentage < 10:
                severity = "medium" if percentage < 5 else "low"
            elif metric_type == MetricType.IMPACT and percentage < 5:
                severity = "low"
            else:
                severity = "none"
            
            if severity != "none":
                gaps[metric_type.value] = {
                    "count": count,
                    "percentage": percentage,
                    "severity": severity,
                    "recommendation": self._get_gap_recommendation(metric_type)
                }
        
        return {
            "metrics_count": total_count,
            "type_counts": {t.value: c for t, c in type_counts.items()},
            "type_percentages": {t.value: p for t, p in type_percentages.items()},
            "gaps": gaps
        }
    
    def _get_type_description(self, metric_type: MetricType) -> str:
        """Get a description for a metric type."""
        descriptions = {
            MetricType.IMPLEMENTATION: "progress of security control implementation, deployment, or compliance",
            MetricType.EFFECTIVENESS: "degree to which security controls are working correctly and producing the desired outcome",
            MetricType.EFFICIENCY: "resources required and timeliness of security control implementation and operation",
            MetricType.IMPACT: "business or mission impact of security controls and their contribution to overall objectives",
            MetricType.UNKNOWN: "security aspects that don't clearly fall into other categories"
        }
        
        return descriptions.get(metric_type, "security aspects")
    
    def _get_gap_recommendation(self, metric_type: MetricType) -> str:
        """Get a recommendation for addressing a gap in a metric type."""
        recommendations = {
            MetricType.IMPLEMENTATION: "Add metrics that track the implementation progress, coverage, or compliance status of security controls.",
            MetricType.EFFECTIVENESS: "Add metrics that measure how well security controls are detecting, preventing, or reducing security incidents.",
            MetricType.EFFICIENCY: "Add metrics that assess the resources required, time taken, or costs associated with security controls.",
            MetricType.IMPACT: "Add metrics that link security measures to business outcomes, financial benefits, or strategic objectives."
        }
        
        return recommendations.get(metric_type, "Consider adding more metrics of this type.")
    
    def create_inventory_report(self):
        """Create and store an inventory report."""
        # Refresh metrics inventory
        self.refresh_metrics_inventory()
        metrics_by_type = self.retrieve_from_memory("metrics_inventory")
        
        # Generate report content
        report_content = f"""# Security Metrics Inventory Report

    ## Overview
    This report provides an inventory of all security metrics in the system, organized by NIST SP 800-55 categories.
    Report generated on: {datetime.datetime.now().isoformat()}

    """
        
        total_metrics = sum(len(metrics) for metrics in metrics_by_type.values())
        report_content += f"Total metrics: {total_metrics}\n\n"
        
        # Add sections for each metric type
        for metric_type, metrics in metrics_by_type.items():
            report_content += f"## {metric_type.value.capitalize()} Metrics ({len(metrics)})\n\n"
            
            if not metrics:
                report_content += "No metrics in this category.\n\n"
                continue
            
            for metric in metrics:
                report_content += f"### {metric.name}\n\n"
                report_content += f"- ID: {metric.id}\n"
                report_content += f"- Description: {metric.description}\n"
                report_content += f"- Formula: {metric.formula}\n"
                report_content += f"- Unit: {metric.unit}\n"
                
                if metric.target is not None:
                    report_content += f"- Target: {metric.target}\n"
                
                if metric.data_source:
                    report_content += f"- Data Source: {metric.data_source}\n"
                
                report_content += "\n"
        
        # Add gap analysis
        gaps = self.identify_gaps()
        report_content += "## Gap Analysis\n\n"
        
        if gaps["gaps"]:
            report_content += "The following gaps were identified in the metrics inventory:\n\n"
            
            for metric_type, gap_info in gaps["gaps"].items():
                report_content += f"### {metric_type.capitalize()}\n\n"
                report_content += f"- Current count: {gap_info['count']}\n"
                report_content += f"- Current percentage: {gap_info['percentage']:.1f}%\n"
                report_content += f"- Severity: {gap_info['severity']}\n"
                report_content += f"- Recommendation: {gap_info['recommendation']}\n\n"
        else:
            report_content += "No significant gaps identified in the metrics inventory.\n\n"
        
        # Store the report if report persistence is available
        try:
            # Method 1: Try to get from parent system reference
            if hasattr(self, 'system') and hasattr(self.system, 'report_persistence'):
                report_id = self.system.report_persistence.store_report(
                    content=report_content,
                    title="Security Metrics Inventory Report",
                    agent_id=self.agent_id,
                    report_type="inventory",
                    metadata={"metric_count": total_metrics}
                )
                logger.info(f"Inventory report stored with ID: {report_id}")
            
            # Method 2: If available through message bus
            elif hasattr(self.message_bus, 'system') and hasattr(self.message_bus.system, 'report_persistence'):
                report_id = self.message_bus.system.report_persistence.store_report(
                    content=report_content,
                    title="Security Metrics Inventory Report",
                    agent_id=self.agent_id,
                    report_type="inventory",
                    metadata={"metric_count": total_metrics}
                )
                logger.info(f"Inventory report stored with ID: {report_id}")
        except Exception as e:
            logger.error(f"Error storing inventory report: {str(e)}")
        
        return report_content