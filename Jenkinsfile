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
                                docker buildx build --platform linux/amd64 --no-cache ./api/ -f ./api/Nuitka.dockerfile -t nativeplanet/anchor-api:${tag}
                                docker buildx build --platform linux/amd64 --no-cache ./wg/ -t nativeplanet/anchor-wg:${tag}
                                docker buildx build --platform linux/amd64 --no-cache ./caddy/ -t nativeplanet/anchor-caddy:${tag}
                                docker push nativeplanet/anchor-api:${tag}
                                docker push nativeplanet/anchor-wg:${tag}
                                docker push nativeplanet/anchor-caddy:${tag}
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