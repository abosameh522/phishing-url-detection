import streamlit as st
from phishing_url_detection.model import load
st.set_page_config(page_title='Phishing URL Detection',page_icon='🛡️')
st.title('Phishing URL Detection')
st.caption('Lexical model for anti-phishing research. It does not fetch or resolve URLs.')
@st.cache_resource
def get_model(): return load()
url=st.text_input('URL',placeholder='https://www.google.com/')
mode=st.selectbox('Operating point',['balanced','strict','sensitive'])
if st.button('Inspect') and url:
 try:
  r=get_model().predict(url,mode); st.metric('Phishing probability',f"{r['probability']:.1%}"); st.write(f"**{r['class'].title()}** · threshold {r['threshold']:.3f}"); st.write('Canonical:',r['canonical_url']); st.write('Reasons:'); [st.write('• '+x) for x in r['reasons']]
 except ValueError as e: st.error(str(e))
