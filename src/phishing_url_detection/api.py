from fastapi import FastAPI
from pydantic import BaseModel, Field
from .model import load
app=FastAPI(title='Phishing URL Detection API',version='2.0.0'); predictor=None
class Request(BaseModel): url: str=Field(min_length=1,max_length=2048); mode: str='balanced'
@app.on_event('startup')
def startup():
 global predictor; predictor=load()
@app.get('/health')
def health(): return {'status':'ok','model_loaded':predictor is not None}
@app.post('/predict')
def predict(req:Request):
 global predictor
 if predictor is None: predictor=load()
 if req.mode not in ('strict','balanced','sensitive'): req.mode='balanced'
 try: return predictor.predict(req.url,req.mode)
 except ValueError as e: return {'error':str(e),'class':'unknown','model_version':'2.0.0'}
