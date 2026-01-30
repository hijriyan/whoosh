import asyncio
from fastapi import FastAPI, WebSocket
from fastapi.websockets import WebSocketDisconnect

app = FastAPI(title="Simple API", description="A simple API", version="0.0.1")

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            msg = await websocket.receive()
            text_msg = msg.get("text")
            if text_msg:
                print("<< text: ", text_msg)
                await websocket.send_text(text_msg)
                print(">> text: ", text_msg)
            else:
                bytes_msg = msg.get("bytes")
                if bytes_msg:
                    print("<< bytes: ", bytes_msg)
                    await websocket.send_bytes(bytes_msg)
                    print(">> bytes: ", bytes_msg)
        except RuntimeError as e:
            if "disconnect message" in str(e):
                print("Client disconnected")
                break
            raise e
        except WebSocketDisconnect:
            print("Client disconnected")
            break
