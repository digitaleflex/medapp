USE medappdb;

ALTER TABLE patient 
ADD COLUMN id_medecin INT AFTER role,
ADD FOREIGN KEY (id_medecin) REFERENCES medecin(id); 