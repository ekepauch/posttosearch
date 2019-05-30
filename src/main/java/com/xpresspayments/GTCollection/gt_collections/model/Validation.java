package com.xpresspayments.GTCollection.gt_collections.model;



import javax.persistence.*;

@Entity
@Table(name = "course")

public class Validation {


    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;

    private String title;
    private String book;


    public Validation() {  }

    public Validation(String title, String book) {
        this.setTitle(title);
        this.setBook(book);
    }


    public Validation(int id, String title, String book) {
        this.setId(id);
        this.setTitle(title);
        this.setBook(book);
    }


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getBook() {
        return book;
    }

    public void setBook(String book) {
        this.book = book;
    }


    @Override
    public String toString() {
        return "Validation{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", book='" + book + '\'' +
                '}';
    }
}
