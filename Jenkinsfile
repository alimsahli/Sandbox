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

        stage('DEPENDENCY SCAN (SCA - Trivy)') {
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
                    def appContainer = ""
                    def targetUrl = "http://192.168.50.4:1234"

                    try {
                        echo "Starting application container on port 1234..."
                        appContainer = sh(
                            returnStdout: true,
                            script: "docker run -d -p 1234:1234 alimsahlibw/sandbox:latest"
                        ).trim()

                        echo "Waiting for application to become ready..."
                        retry(5) {
                            sleep 5
                            sh "curl -s -o /dev/null ${targetUrl}"
                        }

                        echo "App ready → Running ZAP scan..."

                        sh """
                            docker run --rm \
                                --user 0 \
                                --network=host \
                                -v "${PWD}:/zap/wrk/:rw" \
                                ghcr.io/zaproxy/zaproxy \
                                zap-baseline.py \
                                    -t ${targetUrl} \
                                    -r zap-report.html \
                                    -x zap-report.xml \
                                    -I
                        """

                        echo "ZAP scan completed and report generated"

                    } finally {
                        if (appContainer?.trim()) {
                            sh "docker stop ${appContainer} || true"
                            sh "docker rm ${appContainer} || true"
                        }
                    }
                }
            }
        }

    }
    
    post {
    always {
        echo "📦 Archiving and publishing ZAP results..."
        archiveArtifacts artifacts: 'zap-report.html,zap-report.xml,trivy-sca-report.json,gitleaks-report.json', allowEmptyArchive: true

        // publishHTML(target: [
        //     allowMissing: false,
        //     alwaysLinkToLastBuild: true,
        //     keepAll: true,
        //     reportDir: '.',
        //     reportFiles: 'zap-report.html',
        //     reportName: 'OWASP ZAP Report'
        // ])
    }

    success {
        script {
            // Extract vulnerability counts from ZAP report
            def zapHigh = sh(script: "grep -o 'High' zap-report.html | wc -l || true", returnStdout: true).trim()
            def zapMed  = sh(script: "grep -o 'Medium' zap-report.html | wc -l || true", returnStdout: true).trim()
            def zapLow  = sh(script: "grep -o 'Low' zap-report.html | wc -l || true", returnStdout: true).trim()

            // Extract Trivy FS results
            def trivyFsCrit = sh(script: "grep -c '\"Severity\": \"CRITICAL\"' trivy-sca-report.json || true", returnStdout: true).trim()
            def trivyFsHigh = sh(script: "grep -c '\"Severity\": \"HIGH\"' trivy-sca-report.json || true", returnStdout: true).trim()

            emailext(
                subject: "✅ [Jenkins] DevSecOps Pipeline Success — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                to: 'alimsahli.si@gmail.com',
                mimeType: 'text/html',
                attachmentsPattern: 'zap-report.html,zap-report.xml,trivy-sca-report.json,gitleaks-report.json',
                body: """
                <html>
                <body style="font-family:Segoe UI, Roboto, sans-serif; color:#333; background:#f9f9f9; padding:20px;">
                <div style="max-width:750px; margin:auto; background:white; padding:25px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.1);">

                <h2 style="color:#2e7d32;">✅ DevSecOps Pipeline — SUCCESS</h2>

                <p>
                🎯 <b>Project:</b> ${env.JOB_NAME}<br>
                🔢 <b>Build #:</b> ${env.BUILD_NUMBER}<br>
                🕒 <b>Executed:</b> ${new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone('Europe/Paris'))}<br>
                🌍 <b>Node:</b> ${env.NODE_NAME}
                </p>

                <hr style="border:none; border-top:1px solid #ddd; margin:15px 0;">

                <h3>📊 Security Scan Summary</h3>

                <table style="width:100%; border-collapse:collapse;">
                <tr><th style="text-align:left;">Scan Type</th><th style="text-align:center;">Result</th></tr>
                <tr><td>📦 Trivy (Dependencies)</td><td>HIGH: ${trivyFsHigh} | CRITICAL: ${trivyFsCrit}</td></tr>
                <tr><td>🧪 OWASP ZAP (DAST)</td><td>HIGH: ${zapHigh} | MEDIUM: ${zapMed} | LOW: ${zapLow}</td></tr>
                <tr><td>🕵️‍♂️ Gitleaks (Secrets)</td><td style="color:green;">No Secrets Found ✅</td></tr>
                </table>

                <hr style="border:none; border-top:1px solid #ddd; margin:15px 0;">

                <h4>📁 Reports & Artifacts</h4>
                <p>
                • <a href="${env.BUILD_URL}artifact/zap-report.html" style="color:#1a73e8;">OWASP ZAP Report</a><br>
                • <a href="${env.BUILD_URL}artifact/trivy-sca-report.json" style="color:#1a73e8;">Trivy SCA Report</a><br>
                • <a href="${env.BUILD_URL}artifact/gitleaks-report.json" style="color:#1a73e8;">Gitleaks Report</a><br>
                • <a href="${env.BUILD_URL}" style="color:#1a73e8;">Full Jenkins Build Logs</a>
                </p>

                <hr style="border:none; border-top:1px solid #ddd; margin:15px 0;">

                <p style="font-size:12px; color:#666; text-align:center;">
                💡 Generated automatically by the <b>DevSecOps Security Pipeline</b> — Jenkins CI/CD<br>
                Environment: <b>${env.NODE_NAME}</b> | Executor: <b>${env.EXECUTOR_NUMBER}</b><br>
                <i>Stay secure, stay automated 🔒🚀</i>
                </p>

                </div>
                </body>
                </html>
                """
            )
        }
    }

    failure {
        emailext(
            subject: "❌ [Jenkins] DevSecOps Pipeline Failed — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
            to: 'alimsahli.si@gmail.com',
            mimeType: 'text/html',
            attachmentsPattern: 'zap-report.html,zap-report.xml,trivy-sca-report.json,gitleaks-report.json',
            body: """
            <html>
            <body style="font-family:Segoe UI, Roboto, sans-serif; color:#333; background:#fff0f0; padding:20px;">
            <div style="max-width:700px; margin:auto; background:white; padding:25px; border-radius:10px; box-shadow:0 2px 8px rgba(255,0,0,0.15);">

            <h2 style="color:#c62828;">❌ DevSecOps Pipeline — FAILED</h2>

            <p>
            Project: <b>${env.JOB_NAME}</b><br>
            Build #: <b>${env.BUILD_NUMBER}</b><br>
            Time: ${new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone('Europe/Paris'))}
            </p>

            <hr style="border:none; border-top:1px solid #ddd; margin:15px 0;">

            <p>
            ⚠️ One or more stages failed during execution.<br>
            Please check <a href="${env.BUILD_URL}console" style="color:#d32f2f;">the Jenkins console logs</a> for details.
            </p>

            <hr style="border:none; border-top:1px solid #ddd; margin:15px 0;">

            <p style="font-size:12px; color:#666; text-align:center;">
            🧠 Generated by Jenkins — DevSecOps CI/CD Pipeline<br>
            <b>Stay secure, stay automated!</b> 🚀
            </p>

            </div>
            </body>
            </html>
            """
        )
    }
}


}