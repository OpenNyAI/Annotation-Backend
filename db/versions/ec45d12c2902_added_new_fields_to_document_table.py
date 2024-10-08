"""Added new fields to Document table

Revision ID: ec45d12c2902
Revises: 50ff83e93b9e
Create Date: 2024-09-11 19:30:33.669921

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'ec45d12c2902'
down_revision: Union[str, None] = '50ff83e93b9e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('documents', sa.Column('size', sa.Integer(), nullable=False))
    op.add_column('documents', sa.Column('annotator', sa.UUID(), nullable=True))
    op.add_column('documents', sa.Column('reviewer', sa.UUID(), nullable=True))
    op.create_foreign_key(None, 'documents', 'users', ['reviewer'], ['id'])
    op.create_foreign_key(None, 'documents', 'users', ['annotator'], ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'documents', type_='foreignkey')
    op.drop_constraint(None, 'documents', type_='foreignkey')
    op.drop_column('documents', 'reviewer')
    op.drop_column('documents', 'annotator')
    op.drop_column('documents', 'size')
    # ### end Alembic commands ###
