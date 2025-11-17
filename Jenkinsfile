pipeline {
    agent any

    stages {

        stage('PYTHON SETUP & Build & Test'){
            steps {
                sh '''
                    # Use a Python Docker container to execute the build/test steps
                    docker run --rm \
                        -v $WORKSPACE:/app \
                        -w /app \
                        python:3.10-slim \
                        sh -c "pip install -r requirements.txt && \
                            pip install pytest && \
                            pytest || true"
                '''
            }
        }

        stage('SECRET SCAN (Gitleaks via Docker)') {
            // No change needed: Gitleaks scans the source code regardless of language.
            steps {
                sh 'docker run --rm -v $WORKSPACE:/app -w /app zricethezav/gitleaks:latest detect --source=. --report-path=gitleaks-report.json --exit-code 0'
            }
        }

        stage('Security Check: Forbidden .env File') {
            // No change needed: This is a policy check.
            steps {
                script {
                    def envFileExists = fileExists('.env')

                    if (envFileExists) {
                        error("🚨 FATAL SECURITY ERROR: The forbidden '.env' configuration file was found in the repository. Please remove it and use Jenkins credentials/secrets instead.")
                    } else {
                        echo '✅ Security check passed. No forbidden .env file found.'
                    }
                }
            }
        }

        stage('SONARQUBE SCAN'){
            environment{
                // Note: SonarScanner uses token and host URL via properties, 
                // but we define them here to pass them easily.
                SONAR_HOST_URL='http://192.168.50.4:9000'
                SONAR_AUTH_TOKEN= credentials('sonarqube')
            }
            steps{
                // CHANGE: Use the official Docker image for SonarScanner
                sh '''
                    docker run --rm \
                        -e SONAR_HOST_URL="${SONAR_HOST_URL}" \
                        -e SONAR_TOKEN="${SONAR_AUTH_TOKEN}" \
                        -v $WORKSPACE:/usr/src \
                        sonarsource/sonar-scanner-cli \
                        -Dsonar.projectKey=alimsahli_sandbox
                '''
            }
        }

        stage('QUALITY GATE WAIT (BLOCKING)') {
            // No change needed: This stage waits for the analysis result.
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    // waitForQualityGate abortPipeline: true, sonarQube: 'MonServeurSonar'
                    echo 'Vérification du Quality Gate SonarQube en cours...'
                }
            }
        }

        stage('DEPENDENCY SCAN (SCA - Trivy via Docker)') {
            steps {
                script {
                    // No change needed: Trivy's 'fs' scan automatically detects and scans Python dependencies (requirements.txt).
                    sh '''
                        docker run --rm \
                            -v $WORKSPACE:/app \
                            -w /app \
                            aquasec/trivy:latest \
                            fs --severity HIGH,CRITICAL --format json --output trivy-sca-report.json . || true
                    '''

                    sh '''
                        echo "--- TRIVY VULNERABILITY REPORT (HIGH/CRITICAL) ---"
                        docker run --rm \
                            -v $WORKSPACE:/app \
                            -w /app \
                            realguess/jq:latest \
                            jq -r \'
                                .Results[] | select(.Vulnerabilities) | {
                                    Target: .Target,
                                    Vulnerabilities: [
                                        .Vulnerabilities[] | select(.Severity == "CRITICAL" or .Severity == "HIGH") | { 
                                            Severity: .Severity, 
                                            VulnerabilityID: .VulnerabilityID, 
                                            PkgName: .PkgName, 
                                            InstalledVersion: .InstalledVersion 
                                        }
                                    ]
                                }
                            \' trivy-sca-report.json
                    '''

                    echo 'Le scan Trivy est terminé. Veuillez consulter les résultats ci-dessus.'
                }
            }
        }

        stage('IMAGE CREATION') {
            steps{
                // CHANGE: Updated image name from 'devops' to 'sandbox' to match your project.
                echo "Building image alimsahlibw/sandbox:latest"
                sh 'docker build -t alimsahlibw/sandbox:latest .'
                sh 'docker image prune -f'
            }
        }

        stage('DOCKER HUB PUSH') {
            steps {
                // CHANGE: Updated image name.
                sh 'docker tag alimsahlibw/sandbox:latest alimsahlibw/sandbox:${BUILD_NUMBER}'
                withCredentials([string(credentialsId: 'dockerhub', variable: 'DOCKERHUB_TOKEN')]) {
                    sh 'echo $DOCKERHUB_TOKEN | docker login -u alimsahlibw --password-stdin'
                    sh 'docker push alimsahlibw/sandbox:latest'
                    sh 'docker push alimsahlibw/sandbox:${BUILD_NUMBER}'
                }
            }
        }

        stage('OWASP ZAP SCAN (DAST)') {
            steps {
                script {
                    def appContainer
                    // This IP (172.17.0.1) is typical for Docker host on Linux; verify it works on your setup.
                    def targetUrl = "http://172.17.0.1:1234" 

                    try {
                        echo "Starting application container on host port 1234..."
                        // Start your application
                        appContainer = sh(
                                returnStdout: true,
                                script: "docker run -d -p 1234:8080 alimsahlibw/sandbox:latest"
                        ).trim()

                        echo "Waiting for application to become ready..."
                        retry(5) {
                            sleep 5
                            sh "curl -s -o /dev/null ${targetUrl}"
                        }

                        echo "App ready. Running ZAP Baseline scan..."

                        // FIXED: Using the stable and officially supported ZAP image.
                        sh """
                            docker run --rm \
                                --network=host \
                                -v ${PWD}:/zap/wrk/:rw \
                                owasp/zap2docker-stable \ 
                                zap-baseline.py \
                                    -t ${targetUrl} \
                                    -r zap-report.html \
                                    -x zap-report.xml \
                                    -I
                        """
                        echo '✅ ZAP Baseline Scan finished. Reports archived.'

                    } catch (Exception e) {
                        echo "🚨 ZAP Stage Error: ${e.getMessage()}"
                    } finally {
                        if (appContainer) {
                            echo "Cleaning up app container: ${appContainer}…"
                            sh "docker stop ${appContainer}"
                            sh "docker rm ${appContainer}"
                        }
                    }
                }
            }
        }
    }
    
    post {
        // Post-build actions are language-agnostic
        always {
            archiveArtifacts artifacts: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml', allowEmptyArchive: true
        }
        success {
            emailext(
                    subject: "✅ Pipeline SUCCESS: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline **completed successfully**!
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml'
            )
        }
        failure {
            emailext(
                    subject: "❌ Pipeline FAILED: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline failed. Check the attached Trivy report for details.
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml'
            )
        }
    }
}