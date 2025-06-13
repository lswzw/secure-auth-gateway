#!/bin/bash

# 启动认证服务
cd auth_service
go run main.go &
AUTH_PID=$!
cd ..

# 启动后端服务
cd backend
go run main.go &
BACKEND_PID=$!
cd ..

# 启动前端服务
cd frontend/vue-project
npm run dev &
FRONTEND_PID=$!
cd ../..

# 等待所有服务启动
sleep 5

echo "所有服务已启动："
echo "认证服务 PID: $AUTH_PID"
echo "后端服务 PID: $BACKEND_PID"
echo "前端服务 PID: $FRONTEND_PID"

# 等待用户输入 Ctrl+C
echo "按 Ctrl+C 停止所有服务"
trap "kill $AUTH_PID $BACKEND_PID $FRONTEND_PID; exit" INT
wait 