# endpoints
To build the Docker image, run the following command in your terminal (ensure Docker is installed):

```bash
docker build -t flask-camera-api .
```

To run the Docker image, run the following command in your terminal:

```bash
docker run -p 5001:5001 flask-camera-api
```

Now, the Flask microservice will be accessible at http://localhost:5001. You can use a tool like curl or Postman to send HTTP requests to the endpoints.


This microservice contains three endpoints for user registration, login, and logout. The endpoints are:
- /register - Register a new user.
- /login - Log in an existing user, returning a JWT access token.
- /logout - Log out an authenticated user (requires a valid JWT).

The above code adds the following endpoints for CRUD operations:

- POST `/cameras` - Create a new camera.
- GET `/cameras` - Retrieve a list of all cameras.
- GET `/cameras/<int:camera_id>` - Retrieve a single camera by ID.
- PUT `/cameras/<int:camera_id>` - Update an existing camera by ID.
- DELETE `/cameras/<int:camera_id>` - Delete a camera by ID.

These endpoints are protected by JWT authentication, so you need to be logged in to access them. 
To test the microservice, you can use a tool like curl or Postman to send HTTP requests to the endpoints, 
including the appropriate JWT access token in the Authorization header.

For swagger documentation:
http://localhost:5001/apidocs

To test the microservice, you can use a tool like curl or Postman to send HTTP requests to the endpoints.


