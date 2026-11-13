ALTER TABLE employees
  ADD COLUMN phone text,
  ADD COLUMN department text,
  ADD COLUMN job_title text,
  ADD COLUMN work_location text,
  ADD COLUMN employment_type text,
  ADD COLUMN start_date date,
  ADD CONSTRAINT employees_employment_type_check CHECK (employment_type IN ('Full-time','Part-time','Contract','Intern'));
