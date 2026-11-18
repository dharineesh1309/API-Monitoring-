"""File management routes (S3 objects + DynamoDB metadata)."""

import asyncio

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ..deps import get_container, require_auth
from ..models.file_record import FileRecord
from ..schemas.files import FileDeletedResponse, FileListOut, FileOut, FileUploadResponse
from ..services import Container
from ..utils.ids import new_id, now_iso

router = APIRouter(prefix="/files", tags=["files"], dependencies=[Depends(require_auth)])


@router.post("/upload", response_model=FileUploadResponse, status_code=201, summary="Upload a file (S3 + DynamoDB)")
async def upload_file(
    file: UploadFile = File(...),
    container: Container = Depends(get_container),
) -> FileUploadResponse:
    content = await file.read()
    name = file.filename or "unnamed.bin"
    file_id = new_id("file")
    key = f"uploads/{file_id}/{name}"

    # Blocking boto3 calls must not run on the event loop.
    await asyncio.to_thread(
        container.s3.upload,
        key,
        content,
        content_type=file.content_type,
        metadata={"original_filename": name},
    )

    record = FileRecord(
        file_id=file_id,
        name=name,
        size=len(content),
        content_type=file.content_type or "application/octet-stream",
        bucket=container.s3.bucket,
        key=key,
        created_at=now_iso(),
    )
    await asyncio.to_thread(container.dynamodb.put_item, container.dynamodb.files_table, record.to_item())
    container.metrics.file_uploads.add(1, {"status": "ok"})
    return record


@router.get("", response_model=FileListOut, summary="List files (DynamoDB scan)")
def list_files(container: Container = Depends(get_container)) -> FileListOut:
    items = container.dynamodb.latest(container.dynamodb.files_table, limit=50)
    files = [FileRecord.from_item(item) for item in items]
    return FileListOut(files=files, count=len(files))


@router.get("/{file_id}", response_model=FileOut, summary="Get file metadata and presigned download URL (S3)")
def get_file(file_id: str, container: Container = Depends(get_container)) -> FileOut:
    item = container.dynamodb.get_item(container.dynamodb.files_table, {"file_id": file_id})
    if not item:
        raise HTTPException(status_code=404, detail="File not found")
    record = FileRecord.from_item(item)
    return FileOut(**record.to_item(), download_url=container.s3.presigned_url(record.key))


@router.delete("/{file_id}", response_model=FileDeletedResponse, summary="Delete a file (S3 + DynamoDB)")
def delete_file(file_id: str, container: Container = Depends(get_container)) -> FileDeletedResponse:
    item = container.dynamodb.get_item(container.dynamodb.files_table, {"file_id": file_id})
    if not item:
        raise HTTPException(status_code=404, detail="File not found")
    record = FileRecord.from_item(item)
    container.s3.delete(record.key)
    container.dynamodb.delete_item(container.dynamodb.files_table, {"file_id": file_id})
    return FileDeletedResponse(file_id=file_id, deleted=True)
