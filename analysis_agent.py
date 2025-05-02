"""
Security Capability Measurement Program - Analysis Agent Implementation

This module implements the Analysis Agent which is responsible for analyzing
security measurements, providing insights, and generating reports.
"""

import re
import logging
import datetime
import json
import math
import statistics
from typing import Dict, List, Any, Optional, Union, Tuple

# Import components from previous milestones
from environmental import MessageType, MessageContent, AgentMessage
from base_structure import BaseAgent, MessageBus
from data_management import (
    MetricType, MetricStatus, MetricDefinition, MetricValue, 
    MetricManager, DataSourceManager
)

logger = logging.getLogger('security_measurement')

class AnalysisAgent(BaseAgent):
    """
    Agent responsible for analyzing security measurements.
    Handles trend analysis, correlation, reporting, and recommendations.
    """
    
    def __init__(self, agent_id: str, agent_type: str, description: str, message_bus: MessageBus,
                 model_name: str = "llama3.2:latest", temperature: float = 0.1,
                 system_prompt: str = None):
        """Initialize the analysis agent."""
        super().__init__(agent_id, agent_type, description, message_bus, model_name, temperature, system_prompt)
        
        # Initialize components
        self.metric_manager = MetricManager()
        
        # Set up report templates
        self.report_templates = {
            "executive": self._get_executive_report_template(),
            "technical": self._get_technical_report_template(),
            "compliance": self._get_compliance_report_template(),
            "trend": self._get_trend_report_template()
        }
        
        # Store analysis results
        self.analysis_results = {}
        
        # Subscribe to relevant message types
        self.message_bus.subscribe(self.agent_id, [
            MessageType.QUERY.value,
            MessageType.REQUEST.value,
            MessageType.COMMAND.value
        ])
    
    def _get_executive_report_template(self) -> str:
        """Get the template for executive reports."""
        return """
        # Executive Security Metrics Report

        ## Overview
        {overview}

        ## Key Metrics Summary
        {metrics_summary}

        ## Trends and Insights
        {trends_insights}

        ## Recommendations
        {recommendations}
        """
    
    def _get_technical_report_template(self) -> str:
        """Get the template for technical reports."""
        return """
        # Technical Security Metrics Report

        ## Metrics Details
        {metrics_details}

        ## Analysis Methodology
        {analysis_methodology}

        ## Detailed Findings
        {detailed_findings}

        ## Technical Recommendations
        {technical_recommendations}
        """
    
    def _get_compliance_report_template(self) -> str:
        """Get the template for compliance reports."""
        return """
        # Security Compliance Metrics Report

        ## Compliance Overview
        {compliance_overview}

        ## Control Implementation Status
        {control_status}

        ## Gap Analysis
        {gap_analysis}

        ## Remediation Plan
        {remediation_plan}
        """
    
    def _get_trend_report_template(self) -> str:
        """Get the template for trend reports."""
        return """
        # Security Metrics Trend Report

        ## Trend Summary
        {trend_summary}

        ## Metrics Trends
        {metrics_trends}

        ## Correlation Analysis
        {correlation_analysis}

        ## Forecast and Predictions
        {forecast}
        """
    
    def initialize(self):
        """Initialize the analysis agent."""
        self.store_in_memory("reports", {})
        self.store_in_memory("analyses", {})
        self.store_in_memory("generate_test_report", True)

        logger.info(f"AnalysisAgent {self.agent_id} initialized")
        
    def run_cycle(self):
        """Run a processing cycle."""
        logger.debug(f"AnalysisAgent {self.agent_id} run_cycle called")
        
        # Check if we need to generate a test report
        if self.retrieve_from_memory("generate_test_report", False):
            # Check if we have any metrics with data before trying to generate a report
            all_metrics = self.metric_manager.list_metrics()
            has_data = False
            
            for metric in all_metrics:
                values = self.metric_manager.get_metric_values(metric.id)
                if values:
                    has_data = True
                    break
            
            if has_data:
                logger.info(f"AnalysisAgent {self.agent_id} generating test report during first cycle")
                try:
                    test_report = self.generate_report("executive", "initialization test")
                    if test_report:
                        logger.info(f"Initial test report generated successfully")
                    else:
                        logger.warning(f"Failed to generate initial test report")
                except Exception as e:
                    logger.error(f"Error generating initial test report: {str(e)}")
            else:
                logger.info(f"Skipping test report generation - no metric data available yet")
            
            # Clear flag to prevent repeat generation
            self.store_in_memory("generate_test_report", False)
        
        # Process all pending messages
        self.process_messages()
    
    def handle_query(self, message: AgentMessage) -> AgentMessage:
        """
        Handle query messages about security metric analysis.
        
        Args:
            message: Query message
            
        Returns:
            Response message
        """
        query = message.content.content
        logger.info(f"AnalysisAgent received query: {query}")
        
        # Process the query to determine intent
        if re.search(r'(analyze|analysis|insight).*metric', query, re.IGNORECASE):
            # Metric analysis query
            return self._handle_analyze_metric_query(query, message)
        
        elif re.search(r'(report|generate).*report', query, re.IGNORECASE):
            # Report generation query
            logger.info(f"Detected report generation query: {query}")
            return self._handle_report_query(query, message)
        
        elif re.search(r'(trend|correlation).*metric', query, re.IGNORECASE):
            # Trend analysis query
            return self._handle_trend_query(query, message)
        
        elif re.search(r'(recommend|suggest).*metrics?', query, re.IGNORECASE):
            # Recommendation query
            return self._handle_recommendation_query(query, message)
        
        # General query about analysis
        return self._handle_general_analysis_query(query, message)

    def _handle_analyze_metric_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to analyze a specific metric."""
        # Try to extract metric name or ID from query
        metric_match = re.search(r'(analyze|analysis|insight).*metric\s+(.+?)(\s+for|\s+over|\s+in|\s*$)', query, re.IGNORECASE)
        
        if not metric_match:
            return self.create_response_message(
                content="I couldn't understand which metric you want to analyze. Please specify a metric name or ID.",
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
        
        # Parse time period if specified
        period_match = re.search(r'(for|over|in)\s+(.+?)(\s+period|\s*$)', query, re.IGNORECASE)
        period = period_match.group(2).strip() if period_match else "all time"
        
        # Analyze the metric
        analysis = self.analyze_metric(target_metric.id, period)
        
        if not analysis:
            return self.create_response_message(
                content=f"I couldn't perform analysis for metric '{target_metric.name}'. There may not be enough data available.",
                original_message=message
            )
        
        # Format response
        response = f"Analysis of '{target_metric.name}' ({period}):\n\n"
        
        # Current status
        if "current_value" in analysis:
            response += f"Current value: {analysis['current_value']} {target_metric.unit}\n"
        
        # Trend
        if "trend" in analysis:
            trend = analysis["trend"]
            response += f"Trend: {trend['description']}\n"
            response += f"Change: {trend['percentage_change']:.1f}% {trend['direction']}\n"
        
        # Statistics
        if "statistics" in analysis:
            stats = analysis["statistics"]
            response += f"\nStatistics:\n"
            response += f"- Average: {stats['mean']:.2f} {target_metric.unit}\n"
            response += f"- Median: {stats['median']:.2f} {target_metric.unit}\n"
            response += f"- Range: {stats['min']:.2f} - {stats['max']:.2f} {target_metric.unit}\n"
            
            if "standard_deviation" in stats:
                response += f"- Standard Deviation: {stats['standard_deviation']:.2f} {target_metric.unit}\n"
        
        # Insights
        if "insights" in analysis:
            response += f"\nInsights:\n"
            for insight in analysis["insights"]:
                response += f"- {insight}\n"
        
        # Store the analysis for future reference
        self.analysis_results[target_metric.id] = analysis
        self.store_in_memory("analyses", self.analysis_results)
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_report_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to generate a report."""
        logger.info(f"Handling report query: {query}")
        
        # Try to determine report type
        report_type = "executive"  # Default
        
        if re.search(r'(technical|detailed|in-depth)', query, re.IGNORECASE):
            report_type = "technical"
        elif re.search(r'(compliance|regulatory)', query, re.IGNORECASE):
            report_type = "compliance"
        elif re.search(r'(trend|over time)', query, re.IGNORECASE):
            report_type = "trend"
        
        # Parse time period if specified
        period_match = re.search(r'(for|over|in)\s+(.+?)(\s+period|\s*$)', query, re.IGNORECASE)
        period = period_match.group(2).strip() if period_match else "last month"
        
        logger.info(f"Generating {report_type} report for period: {period}")
        
        # Try to generate the report
        if hasattr(self, 'generate_report'):
            # Use the generate_report method if it exists
            report = self.generate_report(report_type, period)
        else:
            # Fallback to direct report generation
            method_name = f"_generate_{report_type}_report"
            if hasattr(self, method_name):
                try:
                    # Analyze metrics
                    all_metrics = self.metric_manager.list_metrics()
                    metrics_analysis = {}
                    
                    for metric in all_metrics:
                        analysis = self.analyze_metric(metric.id, period)
                        if analysis:
                            metrics_analysis[metric.id] = analysis
                    
                    # Call the report generation method
                    report_method = getattr(self, method_name)
                    report = report_method(metrics_analysis, period)
                    
                    # Try to save the report
                    if report and hasattr(self, 'system') and hasattr(self.system, 'report_persistence'):
                        report_title = f"{report_type.capitalize()} Security Metrics Report - {period}"
                        self.system.report_persistence.store_report(
                            content=report,
                            title=report_title,
                            agent_id=self.agent_id,
                            report_type=report_type,
                            metadata={"period": period}
                        )
                except Exception as e:
                    logger.error(f"Error generating report: {str(e)}")
                    report = None
            else:
                logger.warning(f"Method {method_name} not found in AnalysisAgent")
                report = None
        
        if not report:
            return self.create_response_message(
                content=f"I couldn't generate a {report_type} report. There may not be enough data available, or the report generation method is not implemented.",
                original_message=message
            )
        
        # Format response
        response = f"Here is the {report_type} security metrics report for {period}:\n\n"
        response += report
        
        return self.create_response_message(
            content=response,
            original_message=message
        )

    def _generate_insights(self, metric: MetricDefinition, values: List[MetricValue], 
                          stats: Dict[str, Any], trend: Dict[str, Any], 
                          forecast: Optional[Dict[str, Any]]) -> List[str]:
        """
        Generate insights based on metric analysis.
        
        Args:
            metric: Metric definition
            values: List of metric values
            stats: Statistics calculated for the metric
            trend: Trend analysis results
            forecast: Forecast results
            
        Returns:
            List of insight statements
        """
        insights = []
        
        # Insights based on metric type
        if metric.type.value == "implementation":
            if "direction" in trend:
                if trend["direction"] == "increasing":
                    insights.append("Implementation is progressing positively.")
                elif trend["direction"] == "stable" and trend.get("last_value", 0) > 80:
                    insights.append("Implementation has reached a high level and is maintaining it.")
                elif trend["direction"] == "decreasing":
                    insights.append("Implementation progress is regressing, which may indicate process failures.")
        
        
        elif metric.type.value == "effectiveness":
            # Effectiveness metrics measure how well controls are working
            if trend["direction"] == "increasing":
                insights.append("Controls are becoming more effective over time.")
            elif trend["direction"] == "stable" and trend.get("last_value", 0) > 70:
                insights.append("Controls are maintaining good effectiveness.")
            elif trend["direction"] == "decreasing":
                insights.append("Control effectiveness is degrading, which may increase security risk.")
        
        elif metric.type.value == "efficiency":
            # Efficiency metrics often relate to resource usage
            if trend["direction"] == "increasing":
                insights.append("Efficiency is improving, potentially freeing up resources.")
            elif trend["direction"] == "decreasing":
                insights.append("Efficiency is decreasing, which may require resource reallocation.")
        
        elif metric.type.value == "impact":
            # Impact metrics relate to business outcomes
            if trend["direction"] == "increasing":
                insights.append("Security measures are having an increased positive impact on business outcomes.")
            elif trend["direction"] == "decreasing":
                insights.append("The business impact of security measures is declining.")
        
        # Insights based on statistics
        if "outliers" in stats and stats["outliers"]:
            insights.append(f"There are {len(stats['outliers'])} outlier values that may require investigation.")
        
        if "standard_deviation" in stats:
            if stats["standard_deviation"] > (stats["mean"] * 0.5):
                insights.append("The metric shows high variability, which could indicate inconsistent processes.")
            elif stats["standard_deviation"] < (stats["mean"] * 0.1):
                insights.append("The metric shows low variability, indicating consistent processes.")
        
        if stats["max"] - stats["min"] < (stats["mean"] * 0.1):
            insights.append("The metric has remained within a narrow range, suggesting stability.")
        
        # Insights based on forecast
        if forecast:
            if forecast["short_term"]["direction"] != trend["direction"]:
                insights.append(f"The trend is expected to {forecast['short_term']['direction']} in the short term, reversing the current trend.")
            
            if forecast["long_term"]["change"] > 20:
                insights.append("Significant improvement is projected in the long term.")
            elif forecast["long_term"]["change"] < -20:
                insights.append("Significant degradation is projected in the long term, which may require intervention.")
        
        # Target-based insights if target is set
        if metric.target is not None:
            try:
                target = float(metric.target)
                current = trend["last_value"]
                
                if current >= target:
                    insights.append(f"The metric has met or exceeded its target value of {target}.")
                elif current >= target * 0.9:
                    insights.append(f"The metric is close to meeting its target value of {target}.")
                else:
                    insights.append(f"The metric is below its target value of {target}.")
                
                if forecast and forecast["short_term"]["value"] >= target and current < target:
                    insights.append("The metric is projected to meet its target in the short term.")
                elif forecast and forecast["long_term"]["value"] >= target and current < target:
                    insights.append("The metric is projected to meet its target in the long term.")
            except (ValueError, TypeError):
                pass
        
        return insights
    
    def analyze_correlation(self, metric1_id: str, metric2_id: str) -> Optional[Dict[str, Any]]:
        """
        Analyze correlation between two metrics.
        
        Args:
            metric1_id: ID of first metric
            metric2_id: ID of second metric
            
        Returns:
            Correlation analysis results or None if analysis fails
        """
        # Get the metric definitions
        metric1 = self.metric_manager.get_metric(metric1_id)
        metric2 = self.metric_manager.get_metric(metric2_id)
        
        if not metric1 or not metric2:
            logger.warning(f"One or both metrics not found: {metric1_id}, {metric2_id}")
            return None
        
        # Get metric values
        values1 = self.metric_manager.get_metric_values(metric1_id)
        values2 = self.metric_manager.get_metric_values(metric2_id)
        
        if not values1 or not values2:
            logger.warning(f"One or both metrics have no values: {metric1_id}, {metric2_id}")
            return None
        
        # Need to align values by timestamp
        # First, create dictionaries of values keyed by timestamp
        values1_dict = {v.timestamp: v.value for v in values1}
        values2_dict = {v.timestamp: v.value for v in values2}
        
        # Find common timestamps
        common_timestamps = set(values1_dict.keys()).intersection(set(values2_dict.keys()))
        
        if len(common_timestamps) < 3:
            # Try to interpolate missing values if possible
            # This is a simplistic approach - in a real implementation, 
            # you would use more sophisticated interpolation
            
            # Sort all timestamps
            all_timestamps = sorted(list(set(values1_dict.keys()).union(set(values2_dict.keys()))))
            
            if len(all_timestamps) >= 3:
                # Fill in missing values with the closest available value
                for ts in all_timestamps:
                    if ts not in values1_dict:
                        closest_ts = min(values1_dict.keys(), key=lambda x: abs(datetime.datetime.fromisoformat(x) - datetime.datetime.fromisoformat(ts)))
                        values1_dict[ts] = values1_dict[closest_ts]
                    
                    if ts not in values2_dict:
                        closest_ts = min(values2_dict.keys(), key=lambda x: abs(datetime.datetime.fromisoformat(x) - datetime.datetime.fromisoformat(ts)))
                        values2_dict[ts] = values2_dict[closest_ts]
                
                common_timestamps = all_timestamps
            else:
                logger.warning(f"Insufficient common data points for correlation analysis")
                return None
        
        # Extract aligned values
        aligned_values1 = [values1_dict[ts] for ts in common_timestamps]
        aligned_values2 = [values2_dict[ts] for ts in common_timestamps]
        
        # Calculate Pearson correlation coefficient
        try:
            n = len(aligned_values1)
            sum_x = sum(aligned_values1)
            sum_y = sum(aligned_values2)
            sum_xy = sum(x * y for x, y in zip(aligned_values1, aligned_values2))
            sum_xx = sum(x * x for x in aligned_values1)
            sum_yy = sum(y * y for y in aligned_values2)
            
            numerator = n * sum_xy - sum_x * sum_y
            denominator = math.sqrt((n * sum_xx - sum_x * sum_x) * (n * sum_yy - sum_y * sum_y))
            
            if denominator == 0:
                correlation_coefficient = 0
            else:
                correlation_coefficient = numerator / denominator
        except Exception as e:
            logger.error(f"Error calculating correlation: {str(e)}")
            return None
        
        # Interpret correlation coefficient
        if abs(correlation_coefficient) < 0.3:
            strength = "weak"
            interpretation = "There is little to no relationship between these metrics."
        elif abs(correlation_coefficient) < 0.7:
            strength = "moderate"
            interpretation = "There is a moderate relationship between these metrics."
        else:
            strength = "strong"
            interpretation = "There is a strong relationship between these metrics."
        
        if correlation_coefficient > 0:
            direction = "positive"
            interpretation += " As one metric increases, the other tends to increase as well."
        else:
            direction = "negative"
            interpretation += " As one metric increases, the other tends to decrease."
        
        # Generate insights based on metric types
        insights = []
        
        # Implementation and Effectiveness correlation
        if (metric1.type == MetricType.IMPLEMENTATION and metric2.type == MetricType.EFFECTIVENESS) or \
           (metric2.type == MetricType.IMPLEMENTATION and metric1.type == MetricType.EFFECTIVENESS):
            if correlation_coefficient > 0.5:
                insights.append("The implementation of controls is positively affecting their effectiveness.")
            elif correlation_coefficient < -0.5:
                insights.append("Despite implementation progress, effectiveness may be declining, suggesting quality issues.")
        
        # Effectiveness and Efficiency correlation
        if (metric1.type == MetricType.EFFECTIVENESS and metric2.type == MetricType.EFFICIENCY) or \
           (metric2.type == MetricType.EFFECTIVENESS and metric1.type == MetricType.EFFICIENCY):
            if correlation_coefficient > 0.5:
                insights.append("Improved efficiency is associated with better effectiveness, suggesting good resource allocation.")
            elif correlation_coefficient < -0.5:
                insights.append("There may be a trade-off between efficiency and effectiveness that requires balancing.")
        
        # Implementation and Impact correlation
        if (metric1.type == MetricType.IMPLEMENTATION and metric2.type == MetricType.IMPACT) or \
           (metric2.type == MetricType.IMPLEMENTATION and metric1.type == MetricType.IMPACT):
            if correlation_coefficient > 0.5:
                insights.append("Control implementation is having a positive business impact.")
            elif correlation_coefficient < -0.5:
                insights.append("Control implementation may be negatively affecting business outcomes, suggesting reconsideration of approach.")
        
        return {
            "metric1_id": metric1_id,
            "metric1_name": metric1.name,
            "metric2_id": metric2_id,
            "metric2_name": metric2.name,
            "coefficient": correlation_coefficient,
            "strength": strength,
            "direction": direction,
            "interpretation": interpretation,
            "data_points": len(common_timestamps),
            "insights": insights
        }

    def generate_report(self, report_type: str, period: str = "last month") -> Optional[str]:
        """
        Generate a report of the specified type.
        
        Args:
            report_type: Type of report ('executive', 'technical', 'compliance', 'trend')
            period: Time period for the report
            
        Returns:
            Formatted report or None if generation fails
        """
        logger.info(f"AnalysisAgent.generate_report called for {report_type} report, period {period}")
        logger.debug(f"Agent {self.agent_id} system refs - direct: {hasattr(self, 'system')}, " +
                f"via message_bus: {hasattr(self.message_bus, 'system')}")
        logger.debug(f"System on self: {hasattr(self, 'system')}, System on message_bus: {hasattr(self.message_bus, 'system')}")
        
        # Get date range from period
        start_date, end_date = self._parse_period(period)
        logger.debug(f"Date range: {start_date} to {end_date}")
        
        # Get all metrics
        all_metrics = self.metric_manager.list_metrics()
        
        if not all_metrics:
            logger.warning("No metrics available for report generation")
            return None
        
        logger.debug(f"Found {len(all_metrics)} metrics for report")
        
        # Analyze each metric
        metrics_analysis = {}
        
        for metric in all_metrics:
            logger.debug(f"Analyzing metric: {metric.id}")
            analysis = self.analyze_metric(metric.id, period)
            if analysis:
                metrics_analysis[metric.id] = analysis
        
        if not metrics_analysis:
            logger.warning("No metric analyses available for report generation")
            return None
        
        # Generate report based on type
        report_content = None
        report_title = f"{report_type.capitalize()} Security Metrics Report - {period}"
        
        logger.info(f"Generating {report_type} report content with title: '{report_title}'")
        
        if report_type == "executive":
            report_content = self._generate_executive_report(metrics_analysis, period)
        elif report_type == "technical":
            report_content = self._generate_technical_report(metrics_analysis, period)
        elif report_type == "compliance":
            report_content = self._generate_compliance_report(metrics_analysis, period)
        elif report_type == "trend":
            report_content = self._generate_trend_report(metrics_analysis, period)
        else:
            logger.warning(f"Unknown report type: {report_type}")
            return None
        
        if not report_content:
            logger.warning(f"Failed to generate content for {report_type} report")
            return None
        
        logger.info(f"Successfully generated report content, size: {len(report_content)} characters")
        
        # Store the report if report persistence is available
        report_id = None
        try:
            # Method 1: Try to get from parent system reference
            if hasattr(self, 'system') and hasattr(self.system, 'report_persistence'):
                logger.info(f"Storing report via direct system reference")
                
                report_id = self.system.report_persistence.store_report(
                    content=report_content,
                    title=report_title,
                    agent_id=self.agent_id,
                    report_type=report_type,
                    metadata={"period": period}
                )
                
                if report_id:
                    logger.info(f"Report successfully stored with ID: {report_id}")
                else:
                    logger.error(f"Failed to store report: empty report_id returned")
            
            # Method 2: If available through message bus
            elif hasattr(self.message_bus, 'system') and hasattr(self.message_bus.system, 'report_persistence'):
                logger.info(f"Storing report via message_bus system reference")
                
                report_id = self.message_bus.system.report_persistence.store_report(
                    content=report_content,
                    title=report_title,
                    agent_id=self.agent_id,
                    report_type=report_type,
                    metadata={"period": period}
                )
                
                if report_id:
                    logger.info(f"Report successfully stored with ID: {report_id}")
                else:
                    logger.error(f"Failed to store report: empty report_id returned")
            else:
                logger.warning(f"No report persistence system found. System on self: {hasattr(self, 'system')}, " +
                            f"System on message_bus: {hasattr(self.message_bus, 'system')}")
                logger.warning(f"Using memory storage only.")
        except Exception as e:
            logger.error(f"Error storing report: {str(e)}", exc_info=True)
        
        # Store the report locally as well
        reports = self.retrieve_from_memory("reports", {})
        mem_report_id = f"{report_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        reports[mem_report_id] = report_content
        self.store_in_memory("reports", reports)
        logger.info(f"Report stored in agent memory with ID: {mem_report_id}")
        
        return report_content

    def _generate_executive_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate an executive summary report."""
        # Get template
        template = self.report_templates["executive"]
        
        # Organize metrics by type
        metrics_by_type = {}
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            if metric.type not in metrics_by_type:
                metrics_by_type[metric.type] = []
            
            metrics_by_type[metric.type].append((metric, analysis))
        
        # Generate overview section
        overview = f"This report provides an executive summary of security metrics for the period: {period}. "
        overview += f"It covers {len(metrics_analysis)} metrics across {len(metrics_by_type)} categories. "
        
        # Add trend summary
        improving_count = sum(1 for analysis in metrics_analysis.values() 
                            if analysis.get("trend", {}).get("direction") == "increasing")
        declining_count = sum(1 for analysis in metrics_analysis.values() 
                            if analysis.get("trend", {}).get("direction") == "decreasing")
        stable_count = sum(1 for analysis in metrics_analysis.values() 
                          if analysis.get("trend", {}).get("direction") == "stable")
        
        overview += f"Overall, {improving_count} metrics are improving, {stable_count} are stable, and {declining_count} are declining."
        
        # Generate metrics summary section
        metrics_summary = ""
        
        for metric_type, metrics in metrics_by_type.items():
            metrics_summary += f"## {metric_type.value.capitalize()} Metrics\n\n"
            
            for metric, analysis in metrics:
                current_value = analysis.get("current_value", "N/A")
                trend_direction = analysis.get("trend", {}).get("direction", "stable")
                trend_change = analysis.get("trend", {}).get("percentage_change", 0)
                
                metrics_summary += f"### {metric.name}\n\n"
                metrics_summary += f"Current Value: {current_value} {metric.unit}\n\n"
                metrics_summary += f"Trend: {trend_direction.capitalize()} ({trend_change:.1f}%)\n\n"
                
                if "insights" in analysis and analysis["insights"]:
                    metrics_summary += "Key Insight: " + analysis["insights"][0] + "\n\n"
        
        # Generate trends and insights section
        trends_insights = "## Key Trends\n\n"
        
        # Find metrics with significant changes
        significant_metrics = [(metric_id, analysis) for metric_id, analysis in metrics_analysis.items()
                              if abs(analysis.get("trend", {}).get("percentage_change", 0)) > 20]
        
        if significant_metrics:
            for metric_id, analysis in significant_metrics[:3]:  # Top 3 for brevity
                metric = self.metric_manager.get_metric(metric_id)
                if not metric:
                    continue
                
                trend = analysis.get("trend", {})
                
                trends_insights += f"- **{metric.name}**: {trend.get('description', 'No trend data')}. "
                
                if analysis.get("insights"):
                    trends_insights += analysis["insights"][0] + "\n\n"
                else:
                    trends_insights += "\n\n"
        else:
            trends_insights += "No significant trends identified during this period.\n\n"
        
        # Generate recommendations section
        recommendations = "Based on the current metrics analysis, the following actions are recommended:\n\n"
        
        # Find metrics that need attention (declining or below target)
        attention_metrics = []
        
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            trend = analysis.get("trend", {})
            current_value = analysis.get("current_value")
            
            needs_attention = False
            
            if trend.get("direction") == "decreasing" and metric.type != MetricType.EFFICIENCY:
                needs_attention = True
            
            if metric.target is not None and current_value is not None:
                try:
                    if float(current_value) < float(metric.target) * 0.8:
                        needs_attention = True
                except (ValueError, TypeError):
                    pass
            
            if needs_attention:
                attention_metrics.append((metric, analysis))
        
        if attention_metrics:
            for metric, analysis in attention_metrics[:3]:  # Top 3 for brevity
                trend = analysis.get("trend", {})
                
                recommendations += f"1. **{metric.name}**: "
                
                if trend.get("direction") == "decreasing":
                    recommendations += f"Investigate the decline ({trend.get('percentage_change', 0):.1f}%) and develop an improvement plan.\n\n"
                elif metric.target is not None:
                    recommendations += f"Develop a plan to reach the target value of {metric.target} {metric.unit}.\n\n"
        else:
            recommendations += "1. Continue monitoring all metrics and maintain current security practices.\n\n"
            recommendations += "2. Consider developing additional metrics for areas not currently measured.\n\n"
        
        # Fill in template
        report = template.format(
            overview=overview,
            metrics_summary=metrics_summary,
            trends_insights=trends_insights,
            recommendations=recommendations
        )
        
        return report
    
    def _generate_technical_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a technical report."""
        # Get template
        template = self.report_templates["technical"]
        
        # Generate metrics details section
        metrics_details = ""
        
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            metrics_details += f"### {metric.name} ({metric.id})\n\n"
            metrics_details += f"Type: {metric.type.value.capitalize()}\n\n"
            metrics_details += f"Description: {metric.description}\n\n"
            metrics_details += f"Formula: {metric.formula}\n\n"
            metrics_details += f"Unit: {metric.unit}\n\n"
            
            if "statistics" in analysis:
                stats = analysis["statistics"]
                metrics_details += "Statistics:\n"
                
                for key, value in stats.items():
                    if key != "outliers":
                        metrics_details += f"- {key.capitalize()}: {value}\n"
                
                metrics_details += "\n"
            
            if "trend" in analysis:
                trend = analysis["trend"]
                metrics_details += "Trend:\n"
                metrics_details += f"- Direction: {trend.get('direction', 'Unknown')}\n"
                metrics_details += f"- Change: {trend.get('percentage_change', 0):.2f}%\n"
                metrics_details += f"- Volatility: {trend.get('volatility', 'Unknown')}\n\n"
            
            if "forecast" in analysis:
                forecast = analysis["forecast"]
                metrics_details += "Forecast:\n"
                metrics_details += f"- Short-term (1 month): {forecast['short_term']['value']:.2f} ({forecast['short_term']['change']:.2f}%)\n"
                metrics_details += f"- Long-term (6 months): {forecast['long_term']['value']:.2f} ({forecast['long_term']['change']:.2f}%)\n\n"
            
            metrics_details += "\n"
        
        # Generate analysis methodology section
        analysis_methodology = """
        ## Statistical Analysis
        
        The following statistical methods were used to analyze the metrics:
        
        - **Descriptive Statistics**: Mean, median, minimum, maximum, and standard deviation to characterize the distribution of metric values.
        
        - **Trend Analysis**: Calculation of percentage change over time and characterization of trend direction (increasing, decreasing, or stable).
        
        - **Volatility Analysis**: Examination of the average relative change between consecutive measurements to determine volatility.
        
        - **Linear Regression**: Used for forecasting future metric values based on historical data.
        
        ## Data Processing
        
        All metrics were processed as follows:
        
        1. Data collection from various sources
        2. Normalization and validation
        3. Calculation of statistical measures
        4. Trend and forecast analysis
        5. Insight generation
        """
        
        # Generate detailed findings section
        detailed_findings = "## Metric Details\n\n"
        
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            if "insights" not in analysis or not analysis["insights"]:
                continue
            
            detailed_findings += f"### {metric.name}\n\n"
            
            for insight in analysis["insights"]:
                detailed_findings += f"- {insight}\n"
            
            detailed_findings += "\n"
        
        # Generate correlations if we have enough metrics
        if len(metrics_analysis) >= 2:
            detailed_findings += "## Correlation Analysis\n\n"
            
            # Get a few metric pairs for correlation
            metric_ids = list(metrics_analysis.keys())
            pairs_analyzed = 0
            
            for i in range(min(len(metric_ids), 3)):
                for j in range(i + 1, min(len(metric_ids), 4)):
                    correlation = self.analyze_correlation(metric_ids[i], metric_ids[j])
                    
                    if correlation:
                        metric1 = self.metric_manager.get_metric(metric_ids[i])
                        metric2 = self.metric_manager.get_metric(metric_ids[j])
                        
                        detailed_findings += f"### {metric1.name} vs {metric2.name}\n\n"
                        detailed_findings += f"Correlation: {correlation['coefficient']:.2f} ({correlation['strength']} {correlation['direction']})\n\n"
                        detailed_findings += f"Interpretation: {correlation['interpretation']}\n\n"
                        
                        pairs_analyzed += 1
                        
                        if pairs_analyzed >= 3:  # Limit to 3 pairs for brevity
                            break
                
                if pairs_analyzed >= 3:
                    break
        
        # Generate technical recommendations section
        technical_recommendations = "Based on detailed analysis, the following technical recommendations are proposed:\n\n"
        
        # Find metrics with technical issues
        attention_metrics = []
        
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            if "statistics" not in analysis:
                continue
            
            stats = analysis["statistics"]
            
            # Check for high variability
            if "standard_deviation" in stats and "mean" in stats and stats["mean"] != 0:
                coefficient_of_variation = stats["standard_deviation"] / abs(stats["mean"])
                
                if coefficient_of_variation > 0.5:
                    attention_metrics.append((metric, analysis, "high_variability"))
            
            # Check for outliers
            if "outliers" in stats and stats["outliers"]:
                attention_metrics.append((metric, analysis, "outliers"))
        
        if attention_metrics:
            for metric, analysis, issue in attention_metrics:
                technical_recommendations += f"1. **{metric.name}**: "
                
                if issue == "high_variability":
                    technical_recommendations += "Investigate the causes of high variability and implement controls to stabilize measurements.\n\n"
                elif issue == "outliers":
                    technical_recommendations += f"Examine {len(analysis['statistics']['outliers'])} outlier values to determine root causes.\n\n"
        else:
            technical_recommendations += "1. Refine data collection processes to improve measurement accuracy.\n\n"
            technical_recommendations += "2. Implement automated data validation checks to ensure data quality.\n\n"
        
        # Fill in template
        report = template.format(
            metrics_details=metrics_details,
            analysis_methodology=analysis_methodology,
            detailed_findings=detailed_findings,
            technical_recommendations=technical_recommendations
        )
        
        return report
    
    def _generate_compliance_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a compliance report."""
        # Get template
        template = self.report_templates["compliance"]
        
        # Get only implementation metrics for compliance
        implementation_metrics = {}
        for metric_id, analysis in metrics_analysis.items():
            metric = self.metric_manager.get_metric(metric_id)
            if not metric or metric.type != MetricType.IMPLEMENTATION:
                continue
            
            implementation_metrics[metric_id] = (metric, analysis)
        
        if not implementation_metrics:
            logger.warning("No implementation metrics available for compliance report")
            # Create a minimal report with a warning
            return template.format(
                compliance_overview="No implementation metrics available for compliance assessment.",
                control_status="N/A",
                gap_analysis="N/A",
                remediation_plan="N/A"
            )
        
        # Generate compliance overview section
        total_controls = len(implementation_metrics)
        controls_meeting_target = 0
        controls_near_target = 0
        controls_below_target = 0
        
        for metric_id, (metric, analysis) in implementation_metrics.items():
            current_value = analysis.get("current_value")
            
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
        
        compliance_overview = f"This report assesses compliance across {total_controls} security controls for the period: {period}.\n\n"
        
        compliance_overview += f"Overall compliance: {compliance_percentage:.1f}%\n\n"
        compliance_overview += f"- Controls meeting targets: {controls_meeting_target} ({(controls_meeting_target / total_controls * 100):.1f}%)\n"
        compliance_overview += f"- Controls approaching targets: {controls_near_target} ({(controls_near_target / total_controls * 100):.1f}%)\n"
        compliance_overview += f"- Controls below targets: {controls_below_target} ({(controls_below_target / total_controls * 100):.1f}%)\n\n"
        
        # Generate control status section
        control_status = "The following table presents the compliance status of all security controls:\n\n"
        control_status += "| Control | Current Value | Target | Status | Trend |\n"
        control_status += "|---------|--------------|--------|--------|-------|\n"
        
        for metric_id, (metric, analysis) in implementation_metrics.items():
            current_value = analysis.get("current_value", "N/A")
            target = metric.target or "Not set"
            
            # Determine status
            status = "Unknown"
            if metric.target is not None and analysis.get("current_value") is not None:
                try:
                    if float(current_value) >= float(metric.target):
                        status = "Compliant"
                    elif float(current_value) >= float(metric.target) * 0.9:
                        status = "Near Compliant"
                    else:
                        status = "Non-Compliant"
                except (ValueError, TypeError):
                    status = "Not Assessed"
            
            # Get trend
            trend = analysis.get("trend", {}).get("direction", "stable")
            trend_symbol = "→"
            if trend == "increasing":
                trend_symbol = "↑"
            elif trend == "decreasing":
                trend_symbol = "↓"
            
            control_status += f"| {metric.name} | {current_value} {metric.unit} | {target} {metric.unit} | {status} | {trend_symbol} |\n"
        
        # Generate gap analysis section
        gap_analysis = "The following gaps have been identified in security control compliance:\n\n"
        
        non_compliant_controls = []
        for metric_id, (metric, analysis) in implementation_metrics.items():
            current_value = analysis.get("current_value")
            
            if metric.target is not None and current_value is not None:
                try:
                    target = float(metric.target)
                    value = float(current_value)
                    
                    if value < target:
                        gap_percentage = (target - value) / target * 100
                        non_compliant_controls.append((metric, analysis, gap_percentage))
                except (ValueError, TypeError):
                    pass
        
        # Sort by gap percentage (largest first)
        non_compliant_controls.sort(key=lambda x: x[2], reverse=True)
        
        if non_compliant_controls:
            for metric, analysis, gap_percentage in non_compliant_controls:
                gap_analysis += f"- **{metric.name}**: {gap_percentage:.1f}% below target. "
                
                if "insights" in analysis and analysis["insights"]:
                    gap_analysis += analysis["insights"][0] + "\n\n"
                else:
                    gap_analysis += "\n\n"
        else:
            gap_analysis += "No significant compliance gaps identified.\n\n"
        
        # Generate remediation plan section
        remediation_plan = "Based on identified gaps, the following remediation actions are recommended:\n\n"
        
        if non_compliant_controls:
            for i, (metric, analysis, gap_percentage) in enumerate(non_compliant_controls[:5], 1):  # Top 5 for brevity
                remediation_plan += f"{i}. **{metric.name}**: "
                
                if gap_percentage > 50:
                    remediation_plan += "Critical attention required. Develop an immediate action plan to address significant compliance shortfall.\n\n"
                elif gap_percentage > 20:
                    remediation_plan += "Moderate gap exists. Implement targeted improvements within the next quarter.\n\n"
                else:
                    remediation_plan += "Minor gap exists. Continue current improvement efforts to close the gap.\n\n"
        else:
            remediation_plan += "1. Maintain current security controls and monitoring practices.\n\n"
            remediation_plan += "2. Consider setting more ambitious targets for fully compliant controls.\n\n"
        
        # Fill in template
        report = template.format(
            compliance_overview=compliance_overview,
            control_status=control_status,
            gap_analysis=gap_analysis,
            remediation_plan=remediation_plan
        )
        
        return report
    
    def _generate_trend_report(self, metrics_analysis: Dict[str, Any], period: str) -> str:
        """Generate a trend report."""
        # Get template
        template = self.report_templates["trend"]
        
        # Generate trend summary section
        trend_summary = f"This report analyzes trends in security metrics for the period: {period}.\n\n"
        
        # Count trends by direction
        increasing = 0
        decreasing = 0
        stable = 0
        
        for metric_id, analysis in metrics_analysis.items():
            if "trend" not in analysis:
                continue
            
            direction = analysis["trend"].get("direction")
            
            if direction == "increasing":
                increasing += 1
            elif direction == "decreasing":
                decreasing += 1
            elif direction == "stable":
                stable += 1
        
        trend_summary += f"Overall trend summary:\n"
        trend_summary += f"- {increasing} metrics show an increasing trend\n"
        trend_summary += f"- {stable} metrics show a stable trend\n"
        trend_summary += f"- {decreasing} metrics show a decreasing trend\n\n"
        
        # Generate metrics trends section
        metrics_trends = "## Individual Metric Trends\n\n"
        
        # Organize metrics by type
        metrics_by_type = {}
        for metric_id, analysis in metrics_analysis.items():
            if "trend" not in analysis:
                continue
            
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            if metric.type not in metrics_by_type:
                metrics_by_type[metric.type] = []
            
            metrics_by_type[metric.type].append((metric, analysis))
        
        for metric_type, metrics in metrics_by_type.items():
            metrics_trends += f"### {metric_type.value.capitalize()} Metrics\n\n"
            
            for metric, analysis in metrics:
                if "trend" not in analysis:
                    continue
                
                trend = analysis["trend"]
                metrics_trends += f"#### {metric.name}\n\n"
                metrics_trends += f"- Direction: {trend.get('direction', 'Unknown').capitalize()}\n"
                metrics_trends += f"- Change: {trend.get('percentage_change', 0):.1f}%\n"
                metrics_trends += f"- Description: {trend.get('description', 'No description available')}\n"
                
                if "volatility" in trend:
                    metrics_trends += f"- Volatility: {trend['volatility'].capitalize()}\n"
                
                if "forecast" in analysis:
                    forecast = analysis["forecast"]
                    metrics_trends += f"- Forecast (1 month): {forecast['short_term']['direction']} by {abs(forecast['short_term']['change']):.1f}%\n"
                    metrics_trends += f"- Forecast (6 months): {forecast['long_term']['direction']} by {abs(forecast['long_term']['change']):.1f}%\n"
                
                metrics_trends += "\n"
        
        # Generate correlation analysis section
        correlation_analysis = "## Correlation Analysis\n\n"
        
        # Calculate correlations between metrics of different types
        correlations = []
        
        for type1, metrics1 in metrics_by_type.items():
            for type2, metrics2 in metrics_by_type.items():
                if type1 == type2:
                    continue
                
                # Limit to one correlation per type pair
                if metrics1 and metrics2:
                    metric1, _ = metrics1[0]
                    metric2, _ = metrics2[0]
                    
                    correlation = self.analyze_correlation(metric1.id, metric2.id)
                    
                    if correlation and abs(correlation['coefficient']) > 0.3:
                        # Only include moderately strong correlations
                        correlations.append(correlation)
        
        if correlations:
            for correlation in correlations:
                correlation_analysis += f"### {correlation['metric1_name']} vs {correlation['metric2_name']}\n\n"
                correlation_analysis += f"- Correlation: {correlation['coefficient']:.2f} ({correlation['strength']} {correlation['direction']})\n"
                correlation_analysis += f"- Interpretation: {correlation['interpretation']}\n"
                
                if correlation.get('insights'):
                    correlation_analysis += "- Insights:\n"
                    for insight in correlation['insights']:
                        correlation_analysis += f"  - {insight}\n"
                
                correlation_analysis += "\n"
        else:
            correlation_analysis += "No significant correlations were found between metrics of different types.\n\n"
        
        # Generate forecast section
        forecast = "## Forecast and Predictions\n\n"
        
        forecast += "Based on trend analysis, the following projections are made for key metrics:\n\n"
        
        # Find metrics with forecast data
        metrics_with_forecast = []
        for metric_id, analysis in metrics_analysis.items():
            if "forecast" not in analysis:
                continue
            
            metric = self.metric_manager.get_metric(metric_id)
            if not metric:
                continue
            
            metrics_with_forecast.append((metric, analysis))
        
        if metrics_with_forecast:
            for metric, analysis in metrics_with_forecast:
                forecast_data = analysis["forecast"]
                current_value = analysis.get("current_value", 0)
                
                forecast += f"### {metric.name}\n\n"
                forecast += f"Current value: {current_value} {metric.unit}\n\n"
                
                # Short-term forecast
                short_term = forecast_data["short_term"]
                short_term_value = short_term["value"]
                short_term_direction = short_term["direction"]
                short_term_change = short_term["change"]
                
                forecast += f"**1-Month Forecast**: {short_term_value:.2f} {metric.unit} ({short_term_direction} by {abs(short_term_change):.1f}%)\n\n"
                
                # Long-term forecast
                long_term = forecast_data["long_term"]
                long_term_value = long_term["value"]
                long_term_direction = long_term["direction"]
                long_term_change = long_term["change"]
                
                forecast += f"**6-Month Forecast**: {long_term_value:.2f} {metric.unit} ({long_term_direction} by {abs(long_term_change):.1f}%)\n\n"
                
                # Add confidence level based on data points
                values_count = analysis.get("statistics", {}).get("count", 0)
                
                if values_count >= 10:
                    confidence = "High"
                elif values_count >= 5:
                    confidence = "Medium"
                else:
                    confidence = "Low"
                
                forecast += f"Forecast confidence: {confidence} (based on {values_count} data points)\n\n"
        else:
            forecast += "Insufficient data available for reliable forecasting. Consider collecting more data points before generating forecasts.\n\n"
        
        # Fill in template
        report = template.format(
            trend_summary=trend_summary,
            metrics_trends=metrics_trends,
            correlation_analysis=correlation_analysis,
            forecast=forecast
        )
        
        return report
    
    def generate_recommendations(self) -> Dict[str, Any]:
        """
        Generate recommendations for improving metrics and adding new metrics.
        
        Returns:
            Dictionary containing recommendations
        """
        recommendations = {
            "improvement": [],
            "new": []
        }
        
        # Analyze existing metrics for improvement recommendations
        all_metrics = self.metric_manager.list_metrics()
        
        for metric in all_metrics:
            # Get the latest value and analyze
            analysis = self.analyze_metric(metric.id)
            
            if not analysis:
                continue
            
            # Check if metric needs improvement
            needs_improvement = False
            improvement_reason = ""
            
            # Check if metric is declining
            if analysis.get("trend", {}).get("direction") == "decreasing" and metric.type != MetricType.EFFICIENCY:
                needs_improvement = True
                improvement_reason = "declining trend"
            
            # Check if metric is below target
            if metric.target is not None and analysis.get("current_value") is not None:
                try:
                    target = float(metric.target)
                    value = float(analysis["current_value"])
                    
                    if value < target * 0.8:
                        needs_improvement = True
                        improvement_reason = "significantly below target"
                except (ValueError, TypeError):
                    pass
            
            # Check for high volatility
            if analysis.get("trend", {}).get("volatility") == "high":
                needs_improvement = True
                improvement_reason = "high volatility"
            
            if needs_improvement:
                # Generate recommendation for improvement
                recommendation = self._generate_improvement_recommendation(metric, analysis, improvement_reason)
                
                recommendations["improvement"].append({
                    "metric_id": metric.id,
                    "metric_name": metric.name,
                    "reason": improvement_reason,
                    "recommendation": recommendation
                })
        
        # Generate recommendations for new metrics
        # First, analyze coverage of existing metrics
        metrics_by_type = {}
        for metric in all_metrics:
            if metric.type not in metrics_by_type:
                metrics_by_type[metric.type] = []
            
            metrics_by_type[metric.type].append(metric)
        
        # Check for gaps in coverage
        if MetricType.IMPLEMENTATION not in metrics_by_type or len(metrics_by_type.get(MetricType.IMPLEMENTATION, [])) < 3:
            # Need more implementation metrics
            recommendations["new"].append(self._generate_new_metric_recommendation(MetricType.IMPLEMENTATION))
        
        if MetricType.EFFECTIVENESS not in metrics_by_type or len(metrics_by_type.get(MetricType.EFFECTIVENESS, [])) < 2:
            # Need more effectiveness metrics
            recommendations["new"].append(self._generate_new_metric_recommendation(MetricType.EFFECTIVENESS))
        
        if MetricType.EFFICIENCY not in metrics_by_type or len(metrics_by_type.get(MetricType.EFFICIENCY, [])) < 1:
            # Need more efficiency metrics
            recommendations["new"].append(self._generate_new_metric_recommendation(MetricType.EFFICIENCY))
        
        if MetricType.IMPACT not in metrics_by_type:
            # Need impact metrics
            recommendations["new"].append(self._generate_new_metric_recommendation(MetricType.IMPACT))
        
        return recommendations
    
    def _generate_improvement_recommendation(self, metric: MetricDefinition, analysis: Dict[str, Any], reason: str) -> str:
        """
        Generate a recommendation for improving a metric.
        
        Args:
            metric: Metric definition
            analysis: Metric analysis
            reason: Reason for improvement
            
        Returns:
            Improvement recommendation
        """
        if reason == "declining trend":
            if metric.type == MetricType.IMPLEMENTATION:
                return "Review implementation processes and identify barriers to progress. Consider allocating additional resources to accelerate implementation."
            elif metric.type == MetricType.EFFECTIVENESS:
                return "Evaluate the effectiveness of current controls and identify potential weaknesses. Consider conducting a root cause analysis to understand the decline."
            elif metric.type == MetricType.IMPACT:
                return "Reassess the relationship between security measures and business outcomes. Engage with business stakeholders to better align security with business objectives."
            else:
                return "Investigate the causes of the declining trend and develop an action plan to reverse it."
        
        elif reason == "significantly below target":
            return f"Develop a specific action plan to reach the target value of {metric.target} {metric.unit}. Consider setting intermediate milestones and assigning clear responsibility for improvement."
        
        elif reason == "high volatility":
            return "Stabilize the metric by standardizing measurement processes and implementing more consistent controls. Regular monitoring and review can help identify the sources of volatility."
        
        else:
            return "Review current practices and develop an improvement plan based on industry best practices and organizational goals."
    
    def _generate_new_metric_recommendation(self, metric_type: MetricType) -> Dict[str, Any]:
        """
        Generate a recommendation for a new metric of a specific type.
        
        Args:
            metric_type: Type of metric to recommend
            
        Returns:
            New metric recommendation
        """
        if metric_type == MetricType.IMPLEMENTATION:
            return {
                "name": "Security Policy Implementation Rate",
                "description": "Percentage of security policies that have been fully implemented across the organization",
                "type": MetricType.IMPLEMENTATION,
                "formula": "(implemented_policies / total_policies) * 100",
                "unit": "%",
                "rationale": "Provides visibility into the progress of implementing security policies, which is a foundation for a strong security program."
            }
        
        elif metric_type == MetricType.EFFECTIVENESS:
            return {
                "name": "Mean Time to Detect (MTTD)",
                "description": "Average time taken to detect security incidents from the time of occurrence",
                "type": MetricType.EFFECTIVENESS,
                "formula": "sum(detection_times) / count(incidents)",
                "unit": "hours",
                "rationale": "Measures the effectiveness of security monitoring and detection capabilities. Reducing MTTD can minimize the impact of security incidents."
            }
        
        elif metric_type == MetricType.EFFICIENCY:
            return {
                "name": "Security Resource Utilization",
                "description": "Percentage of allocated security resources being actively utilized",
                "type": MetricType.EFFICIENCY,
                "formula": "(used_resources / allocated_resources) * 100",
                "unit": "%",
                "rationale": "Helps optimize the use of security resources and identify opportunities for improved efficiency."
            }
        
        elif metric_type == MetricType.IMPACT:
            return {
                "name": "Security Risk Reduction",
                "description": "Estimated reduction in security risk due to implemented controls",
                "type": MetricType.IMPACT,
                "formula": "((initial_risk - current_risk) / initial_risk) * 100",
                "unit": "%",
                "rationale": "Quantifies the business impact of security measures in terms of risk reduction, which can help justify security investments."
            }
        
        else:
            return {
                "name": "Generic Security Metric",
                "description": "A general security metric to be customized",
                "type": metric_type,
                "formula": "To be determined",
                "unit": "N/A",
                "rationale": "This metric should be customized based on specific organizational needs."
            }
    
    def _handle_report_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query to generate a report."""
        logger.info(f"Handling report query: {query}")
        
        # Try to determine report type
        report_type = "executive"  # Default
        
        if re.search(r'(technical|detailed|in-depth)', query, re.IGNORECASE):
            report_type = "technical"
        elif re.search(r'(compliance|regulatory)', query, re.IGNORECASE):
            report_type = "compliance"
        elif re.search(r'(trend|over time)', query, re.IGNORECASE):
            report_type = "trend"
        
        # Parse time period if specified
        period_match = re.search(r'(for|over|in)\s+(.+?)(\s+period|\s*$)', query, re.IGNORECASE)
        period = period_match.group(2).strip() if period_match else "last month"
        
        logger.info(f"Generating {report_type} report for period: {period}")
        
        # Generate the report using our new method
        report = self.generate_report(report_type, period)
        
        if not report:
            return self.create_response_message(
                content=f"I couldn't generate a {report_type} report. There may not be enough data available.",
                original_message=message
            )
        
        # Format response
        response = f"Here is the {report_type} security metrics report for {period}:\n\n"
        response += report
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_trend_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query about metric trends."""
        # Try to extract metric name or ID from query
        metric_match = re.search(r'(trend|correlation).*metric\s+(.+?)(\s+for|\s+over|\s+in|\s*$)', query, re.IGNORECASE)
        
        # Check if the query is about correlation
        is_correlation = "correlation" in query.lower()
        
        if is_correlation:
            # Handle correlation query
            metrics = []
            
            # Try to extract two metric names
            metrics_match = re.search(r'(between|of)\s+(.+?)\s+and\s+(.+?)(\s+for|\s+over|\s+in|\s*$)', query, re.IGNORECASE)
            
            if metrics_match:
                metric1_name = metrics_match.group(2).strip()
                metric2_name = metrics_match.group(3).strip()
                
                # Find the metrics by name or ID
                all_metrics = self.metric_manager.list_metrics()
                
                for metric in all_metrics:
                    if metric.id.lower() == metric1_name.lower() or metric.name.lower() == metric1_name.lower():
                        metrics.append(metric)
                    elif metric.id.lower() == metric2_name.lower() or metric.name.lower() == metric2_name.lower():
                        metrics.append(metric)
            
            if len(metrics) < 2:
                return self.create_response_message(
                    content="I couldn't understand which metrics you want to correlate. Please specify two metric names.",
                    original_message=message
                )
            
            # Analyze correlation
            correlation = self.analyze_correlation(metrics[0].id, metrics[1].id)
            
            if not correlation:
                return self.create_response_message(
                    content=f"I couldn't analyze the correlation between '{metrics[0].name}' and '{metrics[1].name}'. There may not be enough data available.",
                    original_message=message
                )
            
            # Format response
            response = f"Correlation Analysis between '{metrics[0].name}' and '{metrics[1].name}':\n\n"
            
            response += f"Correlation coefficient: {correlation['coefficient']:.2f}\n"
            response += f"Strength: {correlation['strength']}\n"
            response += f"Direction: {correlation['direction']}\n\n"
            
            response += f"Interpretation: {correlation['interpretation']}\n\n"
            
            if "insights" in correlation:
                response += "Additional insights:\n"
                for insight in correlation["insights"]:
                    response += f"- {insight}\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
            
        elif metric_match:
            # Handle trend query for a specific metric
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
            
            # Parse time period if specified
            period_match = re.search(r'(for|over|in)\s+(.+?)(\s+period|\s*$)', query, re.IGNORECASE)
            period = period_match.group(2).strip() if period_match else "all time"
            
            # Analyze the trend
            analysis = self.analyze_metric(target_metric.id, period)
            
            if not analysis or "trend" not in analysis:
                return self.create_response_message(
                    content=f"I couldn't analyze the trend for metric '{target_metric.name}'. There may not be enough data available.",
                    original_message=message
                )
            
            # Format response
            trend = analysis["trend"]
            response = f"Trend Analysis for '{target_metric.name}' ({period}):\n\n"
            
            response += f"Trend Direction: {trend['direction'].capitalize()}\n"
            response += f"Change: {trend['percentage_change']:.1f}%\n"
            response += f"Summary: {trend['description']}\n\n"
            
            if "forecast" in analysis:
                forecast = analysis["forecast"]
                response += "Forecast:\n"
                response += f"- Short-term (1 month): {forecast['short_term']['direction']} by approximately {forecast['short_term']['change']:.1f}%\n"
                response += f"- Long-term (6 months): {forecast['long_term']['direction']} by approximately {forecast['long_term']['change']:.1f}%\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
        else:
            # Handle general trend query
            # Get all metrics with sufficient data for trend analysis
            all_metrics = self.metric_manager.list_metrics()
            trend_metrics = []
            
            for metric in all_metrics:
                values = self.metric_manager.get_metric_values(metric.id)
                if len(values) >= 3:  # Need at least 3 points for trend
                    trend_metrics.append(metric)
            
            if not trend_metrics:
                return self.create_response_message(
                    content="I couldn't analyze trends for any metrics. There may not be enough historical data available.",
                    original_message=message
                )
            
            # Format response
            response = "Trend Summary for Security Metrics:\n\n"
            
            for metric in trend_metrics[:5]:  # Limit to top 5 for readability
                analysis = self.analyze_metric(metric.id, "all time")
                
                if analysis and "trend" in analysis:
                    trend = analysis["trend"]
                    response += f"'{metric.name}':\n"
                    response += f"- Direction: {trend['direction'].capitalize()}\n"
                    response += f"- Change: {trend['percentage_change']:.1f}%\n"
                    response += f"- Summary: {trend['description']}\n\n"
            
            return self.create_response_message(
                content=response,
                original_message=message
            )
    
    def _handle_recommendation_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a query for metric recommendations."""
        # Analyze existing metrics to provide recommendations
        recommendations = self.generate_recommendations()
        
        if not recommendations:
            return self.create_response_message(
                content="I couldn't generate any recommendations at this time. There may not be enough data available.",
                original_message=message
            )
        
        # Format response
        response = "Security Metric Recommendations:\n\n"
        
        if "improvement" in recommendations:
            response += "Metrics to Improve:\n"
            for rec in recommendations["improvement"]:
                response += f"- {rec['metric_name']}: {rec['recommendation']}\n"
            response += "\n"
        
        if "new" in recommendations:
            response += "Suggested New Metrics:\n"
            for rec in recommendations["new"]:
                response += f"- {rec['name']}: {rec['description']}\n"
                response += f"  Type: {rec['type'].capitalize()}\n"
                response += f"  Rationale: {rec['rationale']}\n\n"
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def _handle_general_analysis_query(self, query: str, message: AgentMessage) -> AgentMessage:
        """Handle a general query about security metric analysis."""
        # Use LLM to generate response about metric analysis
        prompt = f"""
        You are a security metrics analyst following NIST SP 800-55 guidelines.
        A user has asked the following question about security metric analysis:
        
        "{query}"
        
        Provide a helpful response about how security metrics are analyzed and interpreted.
        Focus on analytical approaches, trends, correlations, and insights that can be derived from metrics.
        
        Keep your response concise and focused on security metric analysis techniques.
        """
        
        response = self.query_llm(prompt)
        
        return self.create_response_message(
            content=response,
            original_message=message
        )
    
    def handle_command(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Handle command messages to perform analysis actions.
        
        Args:
            message: Command message
            
        Returns:
            Optional response message
        """
        command = message.content.content
        logger.info(f"AnalysisAgent received command: {command}")
        
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
        if command_type == "analyze_metric":
            return self._handle_analyze_metric_command(command_args, message)
        
        elif command_type == "generate_report":
            return self._handle_generate_report_command(command_args, message)
        
        elif command_type == "analyze_correlation":
            return self._handle_correlation_command(command_args, message)
        
        elif command_type == "generate_recommendations":
            recommendations = self.generate_recommendations()
            return self.create_response_message(
                content=recommendations,
                original_message=message
            )
        
        # Unknown command
        return self.create_error_message(
            error_content=f"Unknown command: {command_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def _handle_analyze_metric_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to analyze a metric."""
        # Parse command arguments
        parts = command_args.split(maxsplit=1)
        if not parts:
            return self.create_error_message(
                error_content="Metric ID not provided for analysis",
                receiver=message.sender,
                reply_to=message.id
            )
        
        metric_id = parts[0]
        period = parts[1] if len(parts) > 1 else "all time"
        
        # Analyze the metric
        analysis = self.analyze_metric(metric_id, period)
        
        if not analysis:
            return self.create_error_message(
                error_content=f"Could not analyze metric with ID '{metric_id}'. Insufficient data may be available.",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Store the analysis
        self.analysis_results[metric_id] = analysis
        self.store_in_memory("analyses", self.analysis_results)
        
        return self.create_response_message(
            content=analysis,
            original_message=message
        )
    
    def _handle_generate_report_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to generate a report."""
        # Parse command arguments
        parts = command_args.split(maxsplit=1)
        if not parts:
            return self.create_error_message(
                error_content="Report type not provided",
                receiver=message.sender,
                reply_to=message.id
            )
        
        report_type = parts[0].lower()
        period = parts[1] if len(parts) > 1 else "last month"
        
        # Validate report type
        if report_type not in self.report_templates:
            return self.create_error_message(
                error_content=f"Unknown report type: {report_type}. Available types: {', '.join(self.report_templates.keys())}",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Generate the report
        report = self.generate_report(report_type, period)
        
        if not report:
            return self.create_error_message(
                error_content=f"Could not generate {report_type} report. Insufficient data may be available.",
                receiver=message.sender,
                reply_to=message.id
            )
        
        # Store the report
        reports = self.retrieve_from_memory("reports", {})
        report_id = f"{report_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        reports[report_id] = report
        self.store_in_memory("reports", reports)
        
        return self.create_response_message(
            content=report,
            original_message=message
        )
    
    def _handle_correlation_command(self, command_args: str, message: AgentMessage) -> AgentMessage:
        """Handle a command to analyze correlation between metrics."""
        # Parse command arguments
        parts = command_args.split()
        if len(parts) < 2:
            return self.create_error_message(
                error_content="Two metric IDs required for correlation analysis",
                receiver=message.sender,
                reply_to=message.id
            )
        
        metric1_id = parts[0]
        metric2_id = parts[1]
        
        # Analyze correlation
        correlation = self.analyze_correlation(metric1_id, metric2_id)
        
        if not correlation:
            return self.create_error_message(
                error_content=f"Could not analyze correlation between metrics '{metric1_id}' and '{metric2_id}'. Insufficient data may be available.",
                receiver=message.sender,
                reply_to=message.id
            )
        
        return self.create_response_message(
            content=correlation,
            original_message=message
        )
    
    def handle_request(self, message: AgentMessage) -> AgentMessage:
        """
        Handle request messages for analysis from other agents.
        
        Args:
            message: Request message
            
        Returns:
            Response message
        """
        request = message.content.content
        logger.info(f"AnalysisAgent received request: {request}")
        
        # Check request type from metadata
        request_type = message.content.metadata.get("request_type", "")
        
        if request_type == "analyze_metric":
            # Request to analyze a metric
            metric_id = request
            
            # Get period from metadata if available
            period = message.content.metadata.get("period", "all time")
            
            # Analyze the metric
            analysis = self.analyze_metric(metric_id, period)
            
            if not analysis:
                return self.create_error_message(
                    error_content=f"Could not analyze metric with ID '{metric_id}'",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            return self.create_response_message(
                content=analysis,
                original_message=message,
                metadata={"response_type": "metric_analysis"}
            )
        
        elif request_type == "generate_report":
            # Request to generate a report
            report_type = request
            
            # Get period from metadata if available
            period = message.content.metadata.get("period", "last month")
            
            # Generate the report
            report = self.generate_report(report_type, period)
            
            if not report:
                return self.create_error_message(
                    error_content=f"Could not generate {report_type} report",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            return self.create_response_message(
                content=report,
                original_message=message,
                metadata={"response_type": "report"}
            )
        
        elif request_type == "analyze_correlation":
            # Request to analyze correlation
            metrics = request.split(",")
            
            if len(metrics) < 2:
                return self.create_error_message(
                    error_content="Two metric IDs required for correlation analysis",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            # Analyze correlation
            correlation = self.analyze_correlation(metrics[0], metrics[1])
            
            if not correlation:
                return self.create_error_message(
                    error_content=f"Could not analyze correlation between metrics '{metrics[0]}' and '{metrics[1]}'",
                    receiver=message.sender,
                    reply_to=message.id
                )
            
            return self.create_response_message(
                content=correlation,
                original_message=message,
                metadata={"response_type": "correlation_analysis"}
            )
        
        elif request_type == "generate_recommendations":
            # Request for recommendations
            recommendations = self.generate_recommendations()
            
            return self.create_response_message(
                content=recommendations,
                original_message=message,
                metadata={"response_type": "recommendations"}
            )
        
        # Unknown request type
        return self.create_error_message(
            error_content=f"Unknown request type: {request_type}",
            receiver=message.sender,
            reply_to=message.id
        )
    
    def analyze_metric(self, metric_id: str, period: str = "all time") -> Optional[Dict[str, Any]]:
        """
        Analyze a metric to provide insights and statistics.
        
        Args:
            metric_id: ID of the metric to analyze
            period: Time period for analysis
            
        Returns:
            Analysis results or None if analysis fails
        """
        # Get the metric definition
        metric = self.metric_manager.get_metric(metric_id)
        if not metric:
            logger.warning(f"Metric with ID '{metric_id}' not found")
            return None
        
        # Get date range from period
        start_date, end_date = self._parse_period(period)
        
        # Get metric values
        values = self.metric_manager.get_metric_values(metric_id, start_date, end_date)
        
        if not values:
            logger.warning(f"No values found for metric '{metric_id}' in period {period}")
            return None
        
        # Sort values by timestamp
        values.sort(key=lambda v: v.timestamp)
        
        # Calculate statistics
        values_list = [v.value for v in values]
        
        try:
            stats = {
                "count": len(values_list),
                "mean": statistics.mean(values_list),
                "median": statistics.median(values_list),
                "min": min(values_list),
                "max": max(values_list)
            }
            
            if len(values_list) >= 2:
                stats["standard_deviation"] = statistics.stdev(values_list)
                
                # Check for outliers (values more than 2 standard deviations from mean)
                stats["outliers"] = []
                for i, value in enumerate(values_list):
                    if abs(value - stats["mean"]) > 2 * stats["standard_deviation"]:
                        stats["outliers"].append(i)
        except statistics.StatisticsError:
            logger.warning(f"Error calculating statistics for metric '{metric_id}'")
            stats = {
                "count": len(values_list),
                "min": min(values_list),
                "max": max(values_list)
            }
        
        # Analyze trend
        trend = self._analyze_trend(values)
        
        # Get latest value
        current_value = values[-1].value if values else None
        
        # Generate forecast if we have enough data
        forecast = None
        if len(values) >= 3:
            forecast = self._forecast_metric(values)
        
        # Generate insights based on data
        insights = self._generate_insights(metric, values, stats, trend, forecast)
        
        # Compile results
        analysis = {
            "metric_id": metric_id,
            "metric_name": metric.name,
            "period": period,
            "current_value": current_value,
            "statistics": stats,
            "trend": trend
        }
        
        if forecast:
            analysis["forecast"] = forecast
        
        if insights:
            analysis["insights"] = insights
        
        return analysis
    
    def _parse_period(self, period_str: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse a period string into start and end dates.
        
        Args:
            period_str: Period string (e.g., 'last month', 'last 30 days', 'all time')
            
        Returns:
            Tuple of (start_date, end_date) as ISO format strings or None
        """
        now = datetime.datetime.now()
        start_date = None
        end_date = now.isoformat()
        
        # Parse common period strings
        if period_str.lower() == "all time":
            # No start date limitation
            pass
        
        elif period_str.lower() == "last month":
            start_date = (now - datetime.timedelta(days=30)).isoformat()
        
        elif period_str.lower() == "last week":
            start_date = (now - datetime.timedelta(days=7)).isoformat()
        
        elif period_str.lower() == "last year":
            start_date = (now - datetime.timedelta(days=365)).isoformat()
        
        elif period_str.lower() == "this month":
            start_date = now.replace(day=1).isoformat()
        
        elif period_str.lower() == "this year":
            start_date = now.replace(month=1, day=1).isoformat()
        
        elif "last" in period_str.lower() and "days" in period_str.lower():
            # Parse "last X days"
            match = re.search(r'last\s+(\d+)\s+days', period_str.lower())
            if match:
                days = int(match.group(1))
                start_date = (now - datetime.timedelta(days=days)).isoformat()
        
        return start_date, end_date
    
    def _analyze_trend(self, values: List[MetricValue]) -> Dict[str, Any]:
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
        
        # Sort values by timestamp if needed
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
        
        # Analyze volatility
        if len(values) >= 3:
            differences = []
            for i in range(1, len(sorted_values)):
                prev = sorted_values[i-1].value
                curr = sorted_values[i].value
                if prev != 0:
                    differences.append(abs((curr - prev) / prev))
                else:
                    differences.append(0)
            
            avg_change = sum(differences) / len(differences)
            
            if avg_change > 0.2:
                volatility = "high"
                description += " with high volatility"
            elif avg_change > 0.1:
                volatility = "moderate"
                description += " with moderate volatility"
            else:
                volatility = "low"
                description += " with low volatility"
        else:
            volatility = "unknown"
        
        return {
            "direction": direction,
            "description": description,
            "percentage_change": percentage_change,
            "volatility": volatility,
            "first_value": first_value,
            "last_value": last_value,
            "duration": f"{sorted_values[0].timestamp} to {sorted_values[-1].timestamp}"
        }
    
    def _forecast_metric(self, values: List[MetricValue]) -> Dict[str, Any]:
        """
        Generate a forecast for a metric based on historical values.
        
        Args:
            values: List of metric values
            
        Returns:
            Forecast results
        """
        # Sort values by timestamp
        sorted_values = sorted(values, key=lambda v: v.timestamp)
        
        # Extract values for calculation
        values_list = [v.value for v in sorted_values]
        
        # Simple linear regression forecast
        x = list(range(len(values_list)))
        y = values_list
        
        # Calculate slope and intercept (y = mx + b)
        n = len(x)
        if n < 2:
            return None
        
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x_i * y_i for x_i, y_i in zip(x, y))
        sum_xx = sum(x_i * x_i for x_i in x)
        
        # Calculate slope
        try:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x * sum_x)
            # Calculate intercept
            intercept = (sum_y - slope * sum_x) / n
        except ZeroDivisionError:
            return None
        
        # Current value
        current_value = values_list[-1]
        
        # Forecast for short-term (1 month ahead)
        short_term_x = len(values_list) + 30  # Assuming daily data points
        short_term_forecast = slope * short_term_x + intercept
        
        # Forecast for long-term (6 months ahead)
        long_term_x = len(values_list) + 180  # Assuming daily data points
        long_term_forecast = slope * long_term_x + intercept
        
        # Calculate percentage changes
        short_term_change = ((short_term_forecast - current_value) / current_value) * 100 if current_value != 0 else 0
        long_term_change = ((long_term_forecast - current_value) / current_value) * 100 if current_value != 0 else 0
        
        # Determine directions
        short_term_direction = "increase" if short_term_change > 0 else "decrease" if short_term_change < 0 else "remain stable"
        long_term_direction = "increase" if long_term_change > 0 else "decrease" if long_term_change < 0 else "remain stable"
        
        return {
            "short_term": {
                "value": short_term_forecast,
                "change": short_term_change,
                "direction": short_term_direction
            },
            "long_term": {
                "value": long_term_forecast,
                "change": long_term_change,
                "direction": long_term_direction
            },
            "model": {
                "slope": slope,
                "intercept": intercept,
                "type": "linear"
            }
        }
    
