pipeline {
    agent {
        label 'java17'
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(
            numToKeepStr: '20',
            artifactNumToKeepStr: '10'
        ))
    }

    environment {
        // Maven
        MAVEN_SETTINGS = '/var/jenkins_home/.m2/settings.xml'
        REPO_ID       = 'snapshots'
        REPO_URL      = "http://${env.MAVEN_URL}/repository/maven-snapshots/"

        // 项目目录
        PROJECT_NAME = "${env.JOB_BASE_NAME}"
        DIR_API      = "${env.DIR_KEY}-api"
        DIR_SERVICE  = "${env.DIR_KEY}-service"

        // Docker/TCR
        TCR_REGISTRY = 'ccr.ccs.tencentyun.com'
        IMAGE_NAME   = "${env.REGISTRY_URL}/${env.JOB_BASE_NAME}:${env.BUILD_NUMBER}"

        // OpenBao AppRole Secret 目录（宿主机只读、0400）；容器内固定映射到 /run/secrets/openbao-*
        // 该目录随部署模板统一维护：缺失即拒绝部署（不得让 -v/--mount 在宿主机静默建目录）
        KMS_APPROLE_DIR     = '/opt/openiov/kms-approle/sec-viam'

        // 启动检查
        STARTUP_MAX_RETRIES = '15'
        STARTUP_INTERVAL    = '5'
    }

    parameters {
        booleanParam(
            name: 'DEPLOY_API',
            defaultValue: false,
            description: '是否构建并发布 API'
        )

        booleanParam(
            name: 'DOCKER_NO_CACHE',
            defaultValue: false,
            description: '构建镜像时是否禁用缓存'
        )
    }

    tools {
        jdk   'temurin-17'
        maven 'M3'
    }

    stages {
        stage('环境检查') {
            steps {
                sh '''
                    set -eu

                    echo '============================== 环境检查 =============================='

                    echo "Jenkins 用户：$(whoami)"
                    echo "项目名称：${PROJECT_NAME}"
                    echo "API 目录：${DIR_API}"
                    echo "Service 目录：${DIR_SERVICE}"
                    echo "镜像名称：${IMAGE_NAME}"

                    java -version
                    mvn -version
                    docker version

                    test -f "${MAVEN_SETTINGS}"
                    test -d "${DIR_SERVICE}"
                    test -f "${DIR_SERVICE}/pom.xml"

                    docker network inspect openiov-management >/dev/null
                '''
            }
        }

        stage('构建并发布 API') {
            when {
                expression {
                    return params.DEPLOY_API
                }
            }

            steps {
                dir("${DIR_API}") {
                    sh '''
                        set -eu

                        echo '============================== 构建并发布 API =============================='

                        mvn \
                            --settings "${MAVEN_SETTINGS}" \
                            --batch-mode \
                            --update-snapshots \
                            clean deploy \
                            -DskipTests \
                            -DaltDeploymentRepository="${REPO_ID}::default::${REPO_URL}"
                    '''
                }
            }
        }

        stage('构建服务镜像') {
            steps {
                script {
                    def noCacheArg = params.DOCKER_NO_CACHE ? '--no-cache' : ''

                    sh """
                        set -eu

                        echo '============================== 构建服务镜像 =============================='

                        SETTINGS_TARGET='${DIR_SERVICE}/settings.xml'
                        MAVEN_TARGET='${DIR_SERVICE}/apache-maven-3.6.3-bin.tar.gz'

                        cleanup_build_files() {
                            rm -f "\${SETTINGS_TARGET}" "\${MAVEN_TARGET}"
                        }

                        trap cleanup_build_files EXIT

                        cp '${MAVEN_SETTINGS}' "\${SETTINGS_TARGET}"
                        cp '/var/jenkins_home/apache-maven-3.6.3-bin.tar.gz' "\${MAVEN_TARGET}"

                        docker build \
                            --network openiov-management \
                            ${noCacheArg} \
                            --tag '${IMAGE_NAME}' \
                            --file '/var/jenkins_home/ServiceDockerfile' \
                            '${DIR_SERVICE}'

                        docker image inspect '${IMAGE_NAME}' >/dev/null
                    """
                }
            }
        }

        stage('上传服务镜像') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'tencent-tcr',
                        usernameVariable: 'TCR_USERNAME',
                        passwordVariable: 'TCR_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -eu

                        echo '============================== 上传服务镜像 =============================='

                        logout_tcr() {
                            docker logout "${TCR_REGISTRY}" >/dev/null 2>&1 || true
                        }

                        trap logout_tcr EXIT

                        echo "${TCR_PASSWORD}" |
                            docker login \
                                --username "${TCR_USERNAME}" \
                                --password-stdin \
                                "${TCR_REGISTRY}"

                        docker push "${IMAGE_NAME}"
                    '''
                }
            }
        }

        stage('部署服务') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'tencent-tcr',
                        usernameVariable: 'TCR_USERNAME',
                        passwordVariable: 'TCR_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -eu

                        echo '============================== 部署服务 =============================='

                        ROLLBACK_CONTAINER="${PROJECT_NAME}-rollback"
                        ROLLBACK_AVAILABLE=0
                        ROLLBACK_IMAGE=''

                        logout_tcr() {
                            docker logout "${TCR_REGISTRY}" >/dev/null 2>&1 || true
                        }

                        rollback() {
                            echo '============================== 部署回滚 =============================='

                            echo "删除启动失败的新容器：${PROJECT_NAME}"
                            docker rm -f "${PROJECT_NAME}" >/dev/null 2>&1 || true

                            if [ "${ROLLBACK_AVAILABLE}" -eq 1 ]; then
                                echo "恢复旧容器：${PROJECT_NAME}"

                                # 回滚必须用旧镜像 + 同一组只读 Secret 挂载重建容器。
                                # 直接 docker start 旧容器会沿用「无挂载」的旧定义，配置为 AppRole 时必然启动失败。
                                docker run \
                                    --detach \
                                    --name "${PROJECT_NAME}" \
                                    --network openiov-management \
                                    --restart unless-stopped \
                                    --env-file /var/jenkins_home/nacos.env \
                                    --mount "type=bind,source=${KMS_APPROLE_DIR}/role-id,target=/run/secrets/openbao-role-id,readonly" \
                                    --mount "type=bind,source=${KMS_APPROLE_DIR}/secret-id,target=/run/secrets/openbao-secret-id,readonly" \
                                    "${ROLLBACK_IMAGE}"

                                docker rm -f "${ROLLBACK_CONTAINER}" >/dev/null 2>&1 || true
                            else
                                echo '没有可用于回滚的旧容器。'
                            fi
                        }

                        deployment_failed() {
                            echo '============================== 部署失败 =============================='
                            echo '新容器最后 500 行日志：'

                            docker logs \
                                --tail 500 \
                                "${PROJECT_NAME}" 2>&1 || true

                            rollback
                            exit 1
                        }

                        trap logout_tcr EXIT

                        # 私有仓库 pull 前必须登录
                        echo "${TCR_PASSWORD}" |
                            docker login \
                                --username "${TCR_USERNAME}" \
                                --password-stdin \
                                "${TCR_REGISTRY}"

                        # 先拉取成功，再停止旧容器
                        echo "拉取镜像：${IMAGE_NAME}"
                        docker pull "${IMAGE_NAME}"

                        # AppRole Secret 前置校验（FW-SEC-DSN-CR-019 / OpenBao AppRole）
                        # Jenkins 运行在容器内，宿主 Secret 目录对它不可见，故用一次性探针容器以
                        # 完全相同的挂载方式校验。源路径缺失时 --mount 由 dockerd 直接报错，
                        # 不会像 -v 那样在宿主机静默创建 root 目录（会堵死后续恢复）。
                        # 校验必须在停止旧容器之前完成。
                        if ! docker run \
                            --rm \
                            --entrypoint sh \
                            --mount "type=bind,source=${KMS_APPROLE_DIR},target=/chk,readonly" \
                            "${IMAGE_NAME}" -c '
                                for f in /chk/role-id /chk/secret-id; do
                                    if [ ! -f "$f" ] || [ ! -r "$f" ] || [ ! -s "$f" ]; then
                                        echo "缺少可读的 AppRole Secret：$f" >&2
                                        exit 1
                                    fi
                                done
                            '; then

                            echo "AppRole Secret 前置校验失败（${KMS_APPROLE_DIR}），拒绝部署"
                            exit 1
                        fi

                        # 清理上一次可能遗留的回滚容器
                        if docker container inspect \
                            "${ROLLBACK_CONTAINER}" >/dev/null 2>&1; then

                            echo "清理遗留回滚容器：${ROLLBACK_CONTAINER}"
                            docker rm -f "${ROLLBACK_CONTAINER}"
                        fi

                        # 保留旧容器用于回滚
                        if docker container inspect \
                            "${PROJECT_NAME}" >/dev/null 2>&1; then

                            echo "停止旧容器：${PROJECT_NAME}"
                            docker stop "${PROJECT_NAME}"

                            echo "保留旧容器用于回滚：${ROLLBACK_CONTAINER}"
                            docker rename \
                                "${PROJECT_NAME}" \
                                "${ROLLBACK_CONTAINER}"

                            ROLLBACK_IMAGE="$(docker inspect \
                                --format '{{.Config.Image}}' \
                                "${ROLLBACK_CONTAINER}")"

                            ROLLBACK_AVAILABLE=1
                        else
                            echo '未发现旧容器，本次为首次部署。'
                        fi

                        # 启动新容器
                        echo "启动新容器：${PROJECT_NAME}"

                        if ! docker run \
                            --detach \
                            --name "${PROJECT_NAME}" \
                            --network openiov-management \
                            --restart unless-stopped \
                            --env-file /var/jenkins_home/nacos.env \
                            --mount "type=bind,source=${KMS_APPROLE_DIR}/role-id,target=/run/secrets/openbao-role-id,readonly" \
                            --mount "type=bind,source=${KMS_APPROLE_DIR}/secret-id,target=/run/secrets/openbao-secret-id,readonly" \
                            "${IMAGE_NAME}"; then

                            echo '新容器创建失败。'
                            rollback
                            exit 1
                        fi

                        echo '开始检查服务启动状态……'

                        count=1
                        SUCCESS=0

                        while [ "${count}" -le "${STARTUP_MAX_RETRIES}" ]
                        do
                            echo "检查服务状态：${count}/${STARTUP_MAX_RETRIES}"

                            # 检查容器是否仍在运行
                            if [ -z "$(docker ps \
                                --quiet \
                                --filter "name=^/${PROJECT_NAME}$")" ]; then

                                echo '容器已经退出。'
                                deployment_failed
                            fi

                            # 检查 Spring Boot 启动日志
                            if docker logs "${PROJECT_NAME}" 2>&1 |
                                grep -Eiq 'Started .+ in .+ seconds'; then

                                SUCCESS=1
                                break
                            fi

                            count=$((count + 1))
                            sleep "${STARTUP_INTERVAL}"
                        done

                        if [ "${SUCCESS}" -ne 1 ]; then
                            echo '服务未在规定时间内完成启动。'
                            deployment_failed
                        fi

                        # 挂载断言：AppRole 凭据必须来自只读 Secret，缺失/可写一律视为部署失败
                        # 用 println 输出「目标 rw」两列，避免在 --format 模板里内嵌引号（Groovy/sh 多层转义易失真）
                        MOUNT_LIST="$(docker inspect \
                            -f '{{range .Mounts}}{{println .Destination .RW}}{{end}}' \
                            "${PROJECT_NAME}" 2>/dev/null || true)"

                        for secret_target in \
                            /run/secrets/openbao-role-id \
                            /run/secrets/openbao-secret-id; do

                            if ! printf '%s\n' "${MOUNT_LIST}" |
                                grep -qx "${secret_target} false"; then

                                echo "AppRole Secret 挂载异常：${secret_target}（期望存在且只读）"
                                echo '当前挂载：'
                                printf '%s\n' "${MOUNT_LIST}"
                                deployment_failed
                            fi
                        done

                        echo '============================== 部署成功 =============================='
                        docker ps \
                            --filter "name=^/${PROJECT_NAME}$" \
                            --format '容器={{.Names}} 镜像={{.Image}} 状态={{.Status}}'

                        # 新服务成功后再删除旧容器
                        if [ "${ROLLBACK_AVAILABLE}" -eq 1 ]; then
                            echo "删除旧容器：${ROLLBACK_CONTAINER}"
                            docker rm -f "${ROLLBACK_CONTAINER}"
                        fi
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "部署成功：${IMAGE_NAME}"
        }

        failure {
            echo "流水线执行失败：${env.BUILD_URL}"
        }

        always {
            sh '''
                docker logout ccr.ccs.tencentyun.com \
                    >/dev/null 2>&1 || true
            '''
        }
    }
}