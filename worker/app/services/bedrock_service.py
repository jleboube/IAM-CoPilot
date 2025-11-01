"""
AWS Bedrock service for AI-powered policy generation
"""
import json
from typing import Any
import boto3
from botocore.exceptions import ClientError
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


class BedrockService:
    """Service for Amazon Bedrock AI operations"""

    def __init__(self):
        """Initialize Bedrock service"""
        self.bedrock_runtime = boto3.client(
            'bedrock-runtime',
            region_name=settings.aws_region
        )
        self.model_id = settings.bedrock_model_id
        self.max_tokens = settings.bedrock_max_tokens
        self.temperature = settings.bedrock_temperature

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate_policy_from_nl(
        self,
        description: str,
        resource_arns: list[str] | None = None,
        principal_type: str = "role"
    ) -> dict[str, Any]:
        """Generate IAM policy from natural language description"""

        # Construct the prompt for Claude
        prompt = self._build_policy_generation_prompt(description, resource_arns, principal_type)

        try:
            # Invoke Claude via Bedrock
            response = self.bedrock_runtime.invoke_model(
                modelId=self.model_id,
                contentType='application/json',
                accept='application/json',
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                })
            )

            # Parse response
            response_body = json.loads(response['body'].read())
            generated_text = response_body['content'][0]['text']

            # Extract JSON from response
            policy_json = self._extract_json_from_response(generated_text)

            logger.info("policy_generated_from_nl", description=description[:100])

            return {
                'policy_document': policy_json,
                'policy_name': self._generate_policy_name(description),
                'description': description,
                'raw_response': generated_text
            }

        except ClientError as e:
            logger.error("bedrock_invocation_failed", error=str(e))
            raise
        except Exception as e:
            logger.error("policy_generation_failed", error=str(e))
            raise

    def _build_policy_generation_prompt(
        self,
        description: str,
        resource_arns: list[str] | None,
        principal_type: str
    ) -> str:
        """Build the prompt for policy generation"""

        resource_context = ""
        if resource_arns:
            resource_context = f"\nSpecific resources to include:\n{json.dumps(resource_arns, indent=2)}"

        prompt = f"""You are an AWS IAM policy expert. Generate a valid IAM policy document in JSON format based on the following description.

Description: {description}
Principal Type: {principal_type}{resource_context}

Requirements:
1. Use the principle of least privilege
2. Be specific with actions (avoid wildcards unless necessary)
3. Include resource ARNs where possible
4. Use IAM policy version "2012-10-17"
5. Ensure the policy is syntactically correct
6. Add conditions where appropriate for enhanced security

Return ONLY the JSON policy document, no explanations or markdown formatting. The response should be valid JSON that can be directly parsed.

Example format:
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::bucket-name/*"]
    }}
  ]
}}

Generate the policy now:"""

        return prompt

    def _extract_json_from_response(self, text: str) -> dict[str, Any]:
        """Extract JSON from Claude's response"""
        # Remove markdown code blocks if present
        text = text.strip()
        if text.startswith('```'):
            # Remove opening ```json or ```
            text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            # Remove closing ```
            if text.endswith('```'):
                text = text[:-3]

        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error("json_extraction_failed", text=text[:200], error=str(e))
            raise ValueError(f"Failed to parse JSON from response: {str(e)}")

    def _generate_policy_name(self, description: str) -> str:
        """Generate a policy name from description"""
        # Take first 5 words, clean them, join with hyphens
        words = description.lower().split()[:5]
        clean_words = [''.join(c for c in word if c.isalnum()) for word in words]
        name = '-'.join(clean_words)
        # Add suffix
        return f"iam-copilot-{name}"[:128]

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def analyze_policy_for_optimization(self, policy_document: dict[str, Any], usage_data: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze a policy and suggest optimizations"""

        usage_data_section = ""
        if usage_data:
            usage_data_json = json.dumps(usage_data, indent=2)
            usage_data_section = f"Usage Data (CloudTrail analysis):\n{usage_data_json}\n"

        prompt = f"""You are an AWS IAM security expert. Analyze the following IAM policy and suggest optimizations for least privilege.

Current Policy:
{json.dumps(policy_document, indent=2)}

{usage_data_section}
Provide:
1. List of potentially excessive permissions
2. Unused permissions (if usage data provided)
3. Security concerns (e.g., wildcards, overly broad resources)
4. Recommended optimized policy
5. Estimated permission reduction percentage

Return your analysis in JSON format with these keys:
- excessive_permissions: array of strings
- unused_permissions: array of strings
- security_concerns: array of strings
- recommended_policy: IAM policy JSON object
- reduction_percentage: integer

Return ONLY the JSON response."""

        try:
            response = self.bedrock_runtime.invoke_model(
                modelId=self.model_id,
                contentType='application/json',
                accept='application/json',
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": self.max_tokens,
                    "temperature": 0.0,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                })
            )

            response_body = json.loads(response['body'].read())
            generated_text = response_body['content'][0]['text']
            analysis = self._extract_json_from_response(generated_text)

            logger.info("policy_analysis_completed")
            return analysis

        except ClientError as e:
            logger.error("policy_analysis_failed", error=str(e))
            raise
