# Annotation Backend : The backend service for Annotation UI

This service is a collection of APIs that are specific to the Annotation UI application which is used to create datasets for RAG benchmarking. It uses FastAPI and PostgreSQL to achieve the task at hand.

# 🔧 1. Installation

To use the code, you need to follow these steps:

1. Clone the repository from GitHub:

   ```bash
   git clone git@github.com:OpenNyAI/Annotation-Backend.git
   ```

2. The code requires **Python 3.10 or higher** and the project follows poetry package system. To install [poetry](https://python-poetry.org/docs/), run the following command in the terminal:

   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. Once poetry is installed, run the following commands to create a virtual environment and install the dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   poetry install
   ```

4. If you don't already have a postgres instance running, please run the below command in the terminal to start a local postgres instance:
   ```bash
   docker compose up postgres
   ```

5. Rename the **.env.template** file to **.env** and populate the respective postgres db values, jwt token secrets, gmail credentials and openai key values into the variables present inside.

6. The last step is the **database migration** to create and update the tables in the given postgres instance. Run the following command in the terminal:

   ```bash
   ./db_scripts/upgrade-db.sh
   ```

# 🏃🏻 2. Running

Once the above installation steps are completed, run the following command in the terminal:

```bash
./tools/run-server.sh
```

* The auth APIs and their specifications can be found in [http://localhost:8080/auth/docs](http://localhost:8080/auth/docs).
* The admin APIs and their specifications can be found in [http://localhost:8080/admin/docs](http://localhost:8080/admin/docs).
* The user APIs and their specifications can be found in [http://localhost:8080/user/docs](http://localhost:8080/user/docs).


# 📃 3. Postgres for indexing

1. Install the pgvector extension in postgres if it is absent

   ```bash
   # For Debian/Ubuntu
   sudo apt-get install pgvector

   # For MacOS
   brew install pgvector

   # For Windows
   pip install pgxnclient
   pgxn install vector
   ```
2. Then in the psql terminal or PostgreSQL client, create the pgvector extension using the below SQL command:

   ```bash
   CREATE EXTENSION IF NOT EXISTS vector;
   ```
