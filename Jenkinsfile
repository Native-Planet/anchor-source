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
                        currentBuild.getRawBuild().getExecutor().interrupt(Result.NOT_BUILT)
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
                                docker buildx build --platform linux/amd64 --no-cache ./api/ -t anchor-api:${tag}
                                docker tag anchor-api:${tag} nativeplanet/anchor-api:${tag}
                                docker buildx build --platform linux/amd64 --no-cache ./wg/ -t anchor-wg:${tag}
                                docker tag anchor-wg:${tag} nativeplanet/anchor-wg:${tag}
                                docker buildx build --platform linux/amd64 --no-cache ./caddy/ -t anchor-caddy:${tag}
                                docker tag anchor-caddy:${tag} nativeplanet/anchor-caddy:${tag}
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