# Release validation (local)

Validate the production container image on your machine before tagging or deploying.

## Prerequisites

- Docker installed and running
- Repository root as the build context

## Checklist

1. **Build the image**

   

2. **Run the container**

   

3. **Probe the health endpoint**

   

   Expected response: 

4. **Stop the container**

   

## Notes

- The image runs  (not , which is demo-only).
- Bind address defaults to  inside the container so port mapping works.
- For durable persistence or live integrations, pass environment variables at run time (see  and ).
