import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle

data = pd.read_csv('phishingwebsitedatafinal.csv')

data.drop(['Domain'],axis=1,inplace=True)

X=data.drop('Label',axis=1)

y=data['Label']

X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.3,random_state=1)

from sklearn.naive_bayes import GaussianNB
model = GaussianNB()
model.fit(X_train,y_train)

y_pred=model.predict(X_test)

print(classification_report(y_test, y_pred))

print(confusion_matrix(y_test,y_pred))

print(accuracy_score(y_test,y_pred)*100)

pickle.dump(model, open('PhishWebDetModel.pkl', 'wb'))