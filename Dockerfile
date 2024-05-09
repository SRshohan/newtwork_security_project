# '''Declaring the version'''
FROM python:3.12

# ''Declaring  the working directory''
WORKDIR /app


# ''Copying for the image'''
COPY . /app

# ''Installing the dependacies ''
RUN pip install --no-cache-dir -r requirements.txt

# ''Change the port ''
EXPOSE 8500

# '''running the command'''
CMD ["streamlit", "run", "app.py", "--server.port=8500"]



