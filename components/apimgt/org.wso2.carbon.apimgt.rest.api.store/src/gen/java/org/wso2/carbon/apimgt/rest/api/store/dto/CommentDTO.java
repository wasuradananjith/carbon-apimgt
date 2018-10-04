package org.wso2.carbon.apimgt.rest.api.store.dto;


import com.google.gson.annotations.SerializedName;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.Objects;

/**
 * CommentDTO
 */
public class CommentDTO   {
  @SerializedName("commentId")
  private String commentId = null;

  @SerializedName("apiId")
  private String apiId = null;

  @SerializedName("category")
  private String category = null;

  @SerializedName("parentCommentId")
  private String parentCommentId = null;

  @SerializedName("entryPoint")
  private String entryPoint = null;

  @SerializedName("username")
  private String username = null;

  @SerializedName("commentText")
  private String commentText = null;

  @SerializedName("createdTime")
  private String createdTime = null;

  @SerializedName("createdBy")
  private String createdBy = null;

  @SerializedName("lastUpdatedTime")
  private String lastUpdatedTime = null;

  @SerializedName("lastUpdatedBy")
  private String lastUpdatedBy = null;

  public CommentDTO commentId(String commentId) {
    this.commentId = commentId;
    return this;
  }

   /**
   * Get commentId
   * @return commentId
  **/
  @ApiModelProperty(required = true, value = "")
  public String getCommentId() {
    return commentId;
  }

  public void setCommentId(String commentId) {
    this.commentId = commentId;
  }

  public CommentDTO apiId(String apiId) {
    this.apiId = apiId;
    return this;
  }

   /**
   * Get apiId
   * @return apiId
  **/
  @ApiModelProperty(required = true, value = "")
  public String getApiId() {
    return apiId;
  }

  public void setApiId(String apiId) {
    this.apiId = apiId;
  }

  public CommentDTO category(String category) {
    this.category = category;
    return this;
  }

   /**
   * Get category
   * @return category
  **/
  @ApiModelProperty(value = "")
  public String getCategory() {
    return category;
  }

  public void setCategory(String category) {
    this.category = category;
  }

  public CommentDTO parentCommentId(String parentCommentId) {
    this.parentCommentId = parentCommentId;
    return this;
  }

   /**
   * Get parentCommentId
   * @return parentCommentId
  **/
  @ApiModelProperty(value = "")
  public String getParentCommentId() {
    return parentCommentId;
  }

  public void setParentCommentId(String parentCommentId) {
    this.parentCommentId = parentCommentId;
  }

  public CommentDTO entryPoint(String entryPoint) {
    this.entryPoint = entryPoint;
    return this;
  }

   /**
   * Get entryPoint
   * @return entryPoint
  **/
  @ApiModelProperty(value = "")
  public String getEntryPoint() {
    return entryPoint;
  }

  public void setEntryPoint(String entryPoint) {
    this.entryPoint = entryPoint;
  }

  public CommentDTO username(String username) {
    this.username = username;
    return this;
  }

   /**
   * If username is not given user invoking the API will be taken as the username. 
   * @return username
  **/
  @ApiModelProperty(required = true, value = "If username is not given user invoking the API will be taken as the username. ")
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public CommentDTO commentText(String commentText) {
    this.commentText = commentText;
    return this;
  }

   /**
   * Get commentText
   * @return commentText
  **/
  @ApiModelProperty(required = true, value = "")
  public String getCommentText() {
    return commentText;
  }

  public void setCommentText(String commentText) {
    this.commentText = commentText;
  }

  public CommentDTO createdTime(String createdTime) {
    this.createdTime = createdTime;
    return this;
  }

   /**
   * Get createdTime
   * @return createdTime
  **/
  @ApiModelProperty(example = "2017-02-20T13:57:16.229+0000", value = "")
  public String getCreatedTime() {
    return createdTime;
  }

  public void setCreatedTime(String createdTime) {
    this.createdTime = createdTime;
  }

  public CommentDTO createdBy(String createdBy) {
    this.createdBy = createdBy;
    return this;
  }

   /**
   * Get createdBy
   * @return createdBy
  **/
  @ApiModelProperty(value = "")
  public String getCreatedBy() {
    return createdBy;
  }

  public void setCreatedBy(String createdBy) {
    this.createdBy = createdBy;
  }

  public CommentDTO lastUpdatedTime(String lastUpdatedTime) {
    this.lastUpdatedTime = lastUpdatedTime;
    return this;
  }

   /**
   * Get lastUpdatedTime
   * @return lastUpdatedTime
  **/
  @ApiModelProperty(example = "2017-02-20T13:57:16.229+0000", value = "")
  public String getLastUpdatedTime() {
    return lastUpdatedTime;
  }

  public void setLastUpdatedTime(String lastUpdatedTime) {
    this.lastUpdatedTime = lastUpdatedTime;
  }

  public CommentDTO lastUpdatedBy(String lastUpdatedBy) {
    this.lastUpdatedBy = lastUpdatedBy;
    return this;
  }

   /**
   * Get lastUpdatedBy
   * @return lastUpdatedBy
  **/
  @ApiModelProperty(value = "")
  public String getLastUpdatedBy() {
    return lastUpdatedBy;
  }

  public void setLastUpdatedBy(String lastUpdatedBy) {
    this.lastUpdatedBy = lastUpdatedBy;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CommentDTO comment = (CommentDTO) o;
    return Objects.equals(this.commentId, comment.commentId) &&
        Objects.equals(this.apiId, comment.apiId) &&
        Objects.equals(this.category, comment.category) &&
        Objects.equals(this.parentCommentId, comment.parentCommentId) &&
        Objects.equals(this.entryPoint, comment.entryPoint) &&
        Objects.equals(this.username, comment.username) &&
        Objects.equals(this.commentText, comment.commentText) &&
        Objects.equals(this.createdTime, comment.createdTime) &&
        Objects.equals(this.createdBy, comment.createdBy) &&
        Objects.equals(this.lastUpdatedTime, comment.lastUpdatedTime) &&
        Objects.equals(this.lastUpdatedBy, comment.lastUpdatedBy);
  }

  @Override
  public int hashCode() {
    return Objects.hash(commentId, apiId, category, parentCommentId, entryPoint, username, commentText, createdTime, createdBy, lastUpdatedTime, lastUpdatedBy);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CommentDTO {\n");
    
    sb.append("    commentId: ").append(toIndentedString(commentId)).append("\n");
    sb.append("    apiId: ").append(toIndentedString(apiId)).append("\n");
    sb.append("    category: ").append(toIndentedString(category)).append("\n");
    sb.append("    parentCommentId: ").append(toIndentedString(parentCommentId)).append("\n");
    sb.append("    entryPoint: ").append(toIndentedString(entryPoint)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("    commentText: ").append(toIndentedString(commentText)).append("\n");
    sb.append("    createdTime: ").append(toIndentedString(createdTime)).append("\n");
    sb.append("    createdBy: ").append(toIndentedString(createdBy)).append("\n");
    sb.append("    lastUpdatedTime: ").append(toIndentedString(lastUpdatedTime)).append("\n");
    sb.append("    lastUpdatedBy: ").append(toIndentedString(lastUpdatedBy)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}

