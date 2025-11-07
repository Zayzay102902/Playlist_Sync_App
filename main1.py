
app = FastAPI()

@app.POST("/create_task")
def create_task(str title ):
    task = { "id": 01,
    "title" : title,
    "done" : flase
    }

