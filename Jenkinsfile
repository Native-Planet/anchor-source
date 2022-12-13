pipeline {
    agent any
    environment {
        reg_pw = credentials('Dockerhub PW')
        environ = sh ( 
            script: '''
                echo $BRANCH_NAME|sed 's@origin/@@g'
            ''',
            returnStdout: true
        ).trim()
    }
    stages {
        stage('Build') {
            environment {
                environ = sh ( 
                    script: '''
                        echo $BRANCH_NAME|sed 's@origin/@@g'
                    ''',
                    returnStdout: true
                ).trim()
                tag = sh ( 
                    script: '''
                        if [ "${environ}" = "dev" ]; then
                            echo "staging"
                        elif [ "${environ}" = "master" ]; then
                            echo "latest"
                        else
                            echo "nobuild"
                        fi
                    ''',
                    returnStdout: true
                ).trim()
            }
            steps {
                script {
                    if( "${tag}" == "nobuild" ) {
                        currentBuild.getRawBuild().getExecutor().interrupt(Result.ABORTED)
                        print("Ignoring branch ${tag}")
                        sleep(1)
                    }
                }
                git url: 'https://github.com/Native-Planet/anchor-source.git', 
                    credentialsId: 'Github token', 
                    branch: "${environ}"
                    sh "docker login -u nativeplanet -p $reg_pw docker.io"
                    dir("${env.WORKSPACE}/"){
                        sh (
                            script: '''
                                docker buildx use xbuilder
                                docker buildx build --push --tag nativeplanet/anchor-api:${tag} --platform linux/amd64,linux/arm64 --no-cache ./api/
                                docker buildx build --push --tag nativeplanet/anchor-wg:${tag} --platform linux/amd64,linux/arm64 --no-cache ./wg/
                                docker buildx build --push --tag nativeplanet/anchor-caddy:${tag} --platform linux/amd64,linux/arm64 --no-cache ./caddy/
                            ''',
                            returnStdout: true
                            )
                    }
            }
        }
    }
        post {
            always {
                cleanWs deleteDirs: true, notFailBuild: true
            }
        }
}