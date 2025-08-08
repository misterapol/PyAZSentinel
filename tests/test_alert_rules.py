"""
Tests for PyAZSentinel alert rules functionality.
"""

import pytest
from unittest.mock import Mock, patch
from pyazsentinel.models import ScheduledAlertRule, AlertSeverity, TriggerOperator, AlertRuleKind
from pyazsentinel.services.alert_rules import AlertRulesService
from pyazsentinel.utils.exceptions import ResourceNotFoundError


class TestAlertRulesService:
    """Test cases for AlertRulesService."""

    @pytest.fixture
    def mock_service(self):
        """Create a mock AlertRulesService for testing."""
        with patch('pyazsentinel.services.alert_rules.AlertRulesService._get_access_token'):
            service = AlertRulesService(
                credential=Mock(),
                subscription_id="test-sub",
                resource_group_name="test-rg",
                workspace_name="test-workspace"
            )
            return service

    @pytest.fixture
    def sample_scheduled_rule(self):
        """Create a sample scheduled alert rule for testing."""
        return ScheduledAlertRule(
            display_name="Test Rule",
            description="Test description",
            severity=AlertSeverity.MEDIUM,
            enabled=True,
            query="SecurityEvent | limit 10",
            query_frequency="PT1H",
            query_period="PT1H",
            trigger_operator=TriggerOperator.GREATER_THAN,
            trigger_threshold=0
        )

    def test_scheduled_rule_creation(self, sample_scheduled_rule):
        """Test creation of a scheduled alert rule."""
        assert sample_scheduled_rule.kind == AlertRuleKind.SCHEDULED
        assert sample_scheduled_rule.display_name == "Test Rule"
        assert sample_scheduled_rule.severity == AlertSeverity.MEDIUM
        assert sample_scheduled_rule.enabled is True
        assert sample_scheduled_rule.trigger_operator == TriggerOperator.GREATER_THAN

    def test_rule_validation(self):
        """Test alert rule validation."""
        # Test invalid query frequency format
        with pytest.raises(ValueError):
            ScheduledAlertRule(
                display_name="Test Rule",
                severity=AlertSeverity.HIGH,
                enabled=True,
                query="test query",
                query_frequency="1H",  # Invalid format
                query_period="PT1H",
                trigger_operator=TriggerOperator.GREATER_THAN,
                trigger_threshold=0
            )

    @patch('pyazsentinel.services.base_service.BaseService._make_request')
    def test_list_alert_rules(self, mock_request, mock_service):
        """Test listing alert rules."""
        # Mock API response
        mock_request.return_value = {
            "value": [
                {
                    "id": "rule1",
                    "properties": {
                        "kind": "Scheduled",
                        "displayName": "Test Rule 1",
                        "enabled": True,
                        "severity": "Medium"
                    }
                }
            ]
        }

        rules = mock_service.list()
        assert len(rules) == 1
        mock_request.assert_called_once()

    @patch('pyazsentinel.services.base_service.BaseService._make_request')
    def test_get_alert_rule_not_found(self, mock_request, mock_service):
        """Test getting a non-existent alert rule."""
        mock_request.side_effect = ResourceNotFoundError("Not found")

        with pytest.raises(ResourceNotFoundError):
            mock_service.get("non-existent-rule")


if __name__ == "__main__":
    pytest.main([__file__])
