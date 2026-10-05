import os
import json
import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
from dataclasses import dataclass
import openrouter
import logging

@dataclass
class Issue:
    severity: str  # "critical", "warning", "info"
    category: str  # "security", "dependencies", "structure", "deployment"
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None

class MLOpsVerification:
    def __init__(self, directory_path: str, use_ai: bool = False, openrouter_api_key: str = None):
        self.directory_path = Path(directory_path)
        self.issues: List[Issue] = []
        self.recommendations: List[str] = []
        self.use_ai = use_ai
        self.ai_insights: List[str] = []
        self.fix_plan: List[Dict[str, Any]] = []

        # Initialize OpenRouter client if AI is enabled
        if self.use_ai and openrouter_api_key:
            openrouter.api_key = openrouter_api_key
            self.client = openrouter.OpenRouter(api_key=openrouter_api_key)
        elif self.use_ai:
            # Try to use environment variable
            try:
                self.client = openrouter.OpenRouter()
            except Exception as e:
                logging.warning(f"AI features disabled: {e}")
                self.use_ai = False

    def run_checks(self, check_types: List[str]) -> Dict[str, Any]:
        """Run specified checks on the directory"""
        self.issues = []
        self.recommendations = []

        if "all" in check_types:
            check_types = ["dependencies", "security", "structure", "deployment"]

        for check_type in check_types:
            if check_type == "dependencies":
                self._check_dependencies()
            elif check_type == "security":
                self._check_security()
            elif check_type == "structure":
                self._check_structure()
            elif check_type == "deployment":
                self._check_deployment()

        # Run AI analysis if enabled
        if self.use_ai:
            self._run_ai_analysis()
            self._generate_intelligent_fix_plan()

        # Calculate deployment readiness score
        readiness_score = self._calculate_readiness_score()

        result = {
            "status": "completed",
            "directory": str(self.directory_path),
            "issues": [self._issue_to_dict(issue) for issue in self.issues],
            "recommendations": self.recommendations,
            "deployment_readiness": readiness_score
        }

        # Add AI insights if available
        if self.use_ai:
            result["ai_insights"] = self.ai_insights
            result["fix_plan"] = self.fix_plan

        return result

    def _check_dependencies(self):
        """Check for dependency-related issues"""
        requirements_file = self.directory_path / "requirements.txt"

        if not requirements_file.exists():
            self.issues.append(Issue(
                severity="critical",
                category="dependencies",
                message="No requirements.txt file found"
            ))
            self.recommendations.append("Create a requirements.txt file with all dependencies")
        else:
            # Check for version pinning
            with open(requirements_file) as f:
                content = f.read()
                lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]

                unpinned_deps = []
                for line in lines:
                    if '==' not in line and '>=' not in line and '~=' not in line:
                        unpinned_deps.append(line)

                if unpinned_deps:
                    self.issues.append(Issue(
                        severity="warning",
                        category="dependencies",
                        message=f"Unpinned dependencies found: {', '.join(unpinned_deps)}",
                        file_path="requirements.txt"
                    ))
                    self.recommendations.append("Pin all dependency versions for reproducible builds")

        # Check for common missing dependencies
        python_files = list(self.directory_path.rglob("*.py"))
        imports = set()

        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                imports.add(alias.name.split('.')[0])
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                imports.add(node.module.split('.')[0])
            except Exception:
                continue

        # Common ML libraries that should be in requirements
        common_ml_libs = {'torch', 'tensorflow', 'sklearn', 'numpy', 'pandas', 'matplotlib', 'seaborn'}
        missing_libs = []

        if requirements_file.exists():
            with open(requirements_file) as f:
                req_content = f.read().lower()
                for lib in common_ml_libs:
                    if lib in imports and lib not in req_content and lib.replace('sklearn', 'scikit-learn') not in req_content:
                        missing_libs.append(lib)

        if missing_libs:
            self.issues.append(Issue(
                severity="warning",
                category="dependencies",
                message=f"Imported libraries not in requirements.txt: {', '.join(missing_libs)}"
            ))

    def _check_security(self):
        """Check for security issues"""
        python_files = list(self.directory_path.rglob("*.py"))

        security_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password detected"),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key detected"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret detected"),
            (r'token\s*=\s*["\'][^"\']+["\']', "Hardcoded token detected"),
            (r'(?<!\.)\beval\s*\(', "Use of eval() function - security risk"),  # Fixed: excludes model.eval()
            (r'(?<!\.)\bexec\s*\(', "Use of exec() function - security risk"),  # Fixed: excludes method.exec()
        ]

        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for i, line in enumerate(lines, 1):
                        for pattern, message in security_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.issues.append(Issue(
                                    severity="critical" if "hardcoded" in message.lower() else "warning",
                                    category="security",
                                    message=message,
                                    file_path=str(py_file.relative_to(self.directory_path)),
                                    line_number=i
                                ))
            except Exception:
                continue

    def _check_structure(self):
        """Check project structure"""
        expected_files = {
            "README.md": "info",
            "requirements.txt": "critical",
            ".gitignore": "warning",
            "Dockerfile": "warning"
        }

        for filename, severity in expected_files.items():
            if not (self.directory_path / filename).exists():
                self.issues.append(Issue(
                    severity=severity,
                    category="structure",
                    message=f"Missing {filename} file"
                ))

        # Check for proper package structure
        if not any(self.directory_path.rglob("__init__.py")):
            self.issues.append(Issue(
                severity="warning",
                category="structure",
                message="No __init__.py files found - may not be a proper Python package"
            ))

        # Check for tests
        test_dirs = ["tests", "test"]
        test_files = list(self.directory_path.rglob("test_*.py")) + list(self.directory_path.rglob("*_test.py"))
        has_test_dir = any((self.directory_path / test_dir).exists() for test_dir in test_dirs)

        if not test_files and not has_test_dir:
            self.issues.append(Issue(
                severity="warning",
                category="structure",
                message="No test files or test directory found"
            ))
            self.recommendations.append("Add unit tests to ensure code reliability")

    def _check_deployment(self):
        """Check deployment readiness"""
        dockerfile = self.directory_path / "Dockerfile"
        docker_compose = self.directory_path / "docker-compose.yml"

        if not dockerfile.exists() and not docker_compose.exists():
            self.issues.append(Issue(
                severity="warning",
                category="deployment",
                message="No Docker configuration found"
            ))
            self.recommendations.append("Add Dockerfile for containerized deployment")

        # Check for environment variable usage
        python_files = list(self.directory_path.rglob("*.py"))
        env_vars_used = set()

        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Look for os.environ usage
                    env_matches = re.findall(r'os\.environ\[?["\']([^"\']+)["\']', content)
                    env_vars_used.update(env_matches)
            except Exception:
                continue

        if env_vars_used:
            env_example = self.directory_path / ".env.example"
            if not env_example.exists():
                self.issues.append(Issue(
                    severity="info",
                    category="deployment",
                    message=f"Environment variables used but no .env.example file: {', '.join(list(env_vars_used)[:3])}"
                ))
                self.recommendations.append("Create .env.example file documenting required environment variables")

        # Check for main entry point
        main_files = ["main.py", "app.py", "run.py"]
        has_main = any((self.directory_path / main_file).exists() for main_file in main_files)

        if not has_main:
            self.issues.append(Issue(
                severity="info",
                category="deployment",
                message="No clear main entry point found (main.py, app.py, run.py)"
            ))

    def _calculate_readiness_score(self) -> float:
        """Calculate deployment readiness score (0-100)"""
        base_score = 100.0

        for issue in self.issues:
            if issue.severity == "critical":
                base_score -= 20
            elif issue.severity == "warning":
                base_score -= 10
            elif issue.severity == "info":
                base_score -= 5

        return max(0.0, base_score)

    def _issue_to_dict(self, issue: Issue) -> Dict[str, Any]:
        """Convert Issue to dictionary"""
        return {
            "severity": issue.severity,
            "category": issue.category,
            "message": issue.message,
            "file_path": issue.file_path,
            "line_number": issue.line_number
        }

    # ========================================
    # AI AGENT CAPABILITIES
    # ========================================

    def _run_ai_analysis(self):
        """AI-powered analysis of the project"""
        if not self.use_ai:
            return

        try:
            # Get project overview for AI analysis
            project_overview = self._get_project_overview()

            # AI Analysis: Overall project health
            overall_analysis = self._ai_analyze_project_health(project_overview)
            if overall_analysis:
                self.ai_insights.append(f"🤖 AI Project Analysis: {overall_analysis}")

            # AI Analysis: Code quality issues
            code_analysis = self._ai_analyze_code_patterns()
            if code_analysis:
                self.ai_insights.extend(code_analysis)

            # AI Analysis: Deployment recommendations
            deployment_analysis = self._ai_analyze_deployment_readiness()
            if deployment_analysis:
                self.ai_insights.append(f"🚀 AI Deployment Insights: {deployment_analysis}")

        except Exception as e:
            logging.warning(f"AI analysis failed: {e}")
            self.ai_insights.append("⚠️ AI analysis unavailable")

    def _get_project_overview(self) -> Dict[str, Any]:
        """Get high-level project structure for AI analysis"""
        overview = {
            "total_python_files": len(list(self.directory_path.rglob("*.py"))),
            "has_requirements": (self.directory_path / "requirements.txt").exists(),
            "has_dockerfile": (self.directory_path / "Dockerfile").exists(),
            "has_tests": len(list(self.directory_path.rglob("test_*.py"))) > 0,
            "directories": [d.name for d in self.directory_path.iterdir() if d.is_dir() and not d.name.startswith('.')],
            "main_files": [f.name for f in self.directory_path.glob("*.py")],
            "current_issues": len(self.issues),
            "issue_categories": list(set(issue.category for issue in self.issues))
        }
        return overview

    def _ai_analyze_project_health(self, project_overview: Dict[str, Any]) -> str:
        """AI analysis of overall project health"""
        try:
            prompt = f"""
            As an MLOps expert, analyze this ML project structure and provide insights:

            Project Overview:
            - Python files: {project_overview['total_python_files']}
            - Has requirements.txt: {project_overview['has_requirements']}
            - Has Dockerfile: {project_overview['has_dockerfile']}
            - Has tests: {project_overview['has_tests']}
            - Directories: {', '.join(project_overview['directories'])}
            - Main files: {', '.join(project_overview['main_files'])}
            - Current issues found: {project_overview['current_issues']}
            - Issue types: {', '.join(project_overview['issue_categories'])}

            Provide a concise assessment (2-3 sentences) of:
            1. Overall project maturity
            2. Key strengths or weaknesses
            3. MLOps readiness level

            Be specific and actionable.
            """

            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logging.warning(f"AI project analysis failed: {e}")
            return ""

    def _ai_analyze_code_patterns(self) -> List[str]:
        """AI analysis of specific code files"""
        insights = []

        try:
            # Analyze main Python files
            main_files = list(self.directory_path.glob("*.py"))[:2]  # Limit to 2 files for cost

            for file_path in main_files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()[:2000]  # Limit content for cost

                    if len(content.strip()) < 50:  # Skip tiny files
                        continue

                    prompt = f"""
                    Analyze this ML project file for deployment issues:

                    File: {file_path.name}
                    Code snippet:
                    ```python
                    {content}
                    ```

                    Look for:
                    - Hard-coded values that should be configurable
                    - Missing error handling
                    - Performance concerns
                    - Security issues
                    - MLOps best practice violations

                    Provide 1-2 specific, actionable insights (not general advice).
                    """

                    response = self.client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=150,
                        temperature=0.3
                    )

                    insight = response.choices[0].message.content.strip()
                    if insight and len(insight) > 10:
                        insights.append(f"📄 {file_path.name}: {insight}")

                except Exception as e:
                    logging.warning(f"Failed to analyze {file_path}: {e}")
                    continue

        except Exception as e:
            logging.warning(f"Code pattern analysis failed: {e}")

        return insights

    def _ai_analyze_deployment_readiness(self) -> str:
        """AI analysis of deployment readiness"""
        try:
            # Check for key deployment files
            has_docker = (self.directory_path / "Dockerfile").exists()
            has_compose = (self.directory_path / "docker-compose.yml").exists()
            has_requirements = (self.directory_path / "requirements.txt").exists()
            has_readme = (self.directory_path / "README.md").exists()

            current_score = self._calculate_readiness_score()
            issue_summary = ", ".join([f"{issue.category}: {issue.message[:50]}..." for issue in self.issues[:3]])

            prompt = f"""
            As an MLOps deployment expert, assess this ML project's deployment readiness:

            Infrastructure:
            - Docker: {has_docker}
            - Docker Compose: {has_compose}
            - Requirements: {has_requirements}
            - Documentation: {has_readme}

            Current Issues: {issue_summary}
            Readiness Score: {current_score}/100

            Provide specific deployment recommendations:
            1. What's the biggest deployment risk?
            2. What should be prioritized first?
            3. One concrete next step

            Be concise and actionable (2-3 sentences max).
            """

            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150,
                temperature=0.3
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logging.warning(f"Deployment analysis failed: {e}")
            return ""

    def _generate_intelligent_fix_plan(self):
        """AI-generated step-by-step fix plan"""
        if not self.use_ai or not self.issues:
            return

        try:
            issues_summary = []
            for issue in self.issues[:5]:  # Limit to top 5 issues
                issues_summary.append({
                    "severity": issue.severity,
                    "category": issue.category,
                    "message": issue.message,
                    "file": issue.file_path
                })

            prompt = f"""
            Create a prioritized action plan to fix these MLOps issues:

            Issues:
            {json.dumps(issues_summary, indent=2)}

            Generate a step-by-step fix plan with:
            1. Priority order (critical first)
            2. Specific actions
            3. Dependencies between fixes
            4. Estimated effort (minutes)

            Return as JSON array:
            [
              {{
                "step": 1,
                "priority": "high",
                "action": "specific action description",
                "files_affected": ["file1.py"],
                "estimated_minutes": 15
              }}
            ]
            """

            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=400,
                temperature=0.3
            )

            try:
                # Parse AI response as JSON
                plan_text = response.choices[0].message.content.strip()
                # Extract JSON from response (handle markdown code blocks)
                if "```json" in plan_text:
                    plan_text = plan_text.split("```json")[1].split("```")[0]
                elif "```" in plan_text:
                    plan_text = plan_text.split("```")[1].split("```")[0]

                self.fix_plan = json.loads(plan_text)

            except json.JSONDecodeError:
                # Fallback: create simple plan
                self.fix_plan = [{
                    "step": 1,
                    "priority": "high",
                    "action": "Fix critical issues first, then address warnings",
                    "files_affected": [issue.file_path for issue in self.issues if issue.file_path],
                    "estimated_minutes": len(self.issues) * 10
                }]

        except Exception as e:
            logging.warning(f"Fix plan generation failed: {e}")
            self.fix_plan = []